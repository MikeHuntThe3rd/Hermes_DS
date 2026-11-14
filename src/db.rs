#![allow(warnings)]
use std::{ops::DerefMut, vec};

use crate::{responses::error_t::InternalError, types::*};
use ed25519_dalek::pkcs8::Error::ParametersMalformed;
use sqlx::{
    Database, Encode, Executor, FromRow, IntoArguments, Pool, QueryBuilder, Transaction,
    pool::PoolConnection, query::Query,
};

#[derive(Clone)]
pub struct DbInterface<C>
where
    C: Connect,
{
    connector: C,
}

pub struct DbPool<DB>
where
    DB: Database,
{
    pool: Pool<DB>,
}

impl<DB: Database> Clone for DbPool<DB> {
    fn clone(&self) -> Self {
        return Self {
            pool: self.pool.clone(),
        };
    }
}

impl<DB> Connect for DbPool<DB>
where
    DB: Database,
{
    type DB = DB;
    type Conn<'a> = PoolConnection<DB>;

    async fn conn(&mut self) -> Result<Self::Conn<'_>, InternalError> {
        return Ok(self
            .pool
            .acquire()
            .await
            .map_err(|_| InternalError::DbError)?);
    }
}

impl<DB: Database> DbInterface<DbPool<DB>> {
    pub async fn begin_transaction(
        &mut self,
    ) -> Result<DbInterface<DbTransaction<DB>>, InternalError> {
        return Ok(DbInterface {
            connector: DbTransaction {
                conn: self
                    .connector
                    .pool
                    .begin()
                    .await
                    .map_err(|_| InternalError::DbError)?,
            },
        });
    }

    pub async fn new(pool: Pool<DB>) -> Result<DbInterface<DbPool<DB>>, sqlx::Error> {
        return Ok(Self {
            connector: DbPool { pool: pool },
        });
    }
}

pub struct DbTransaction<DB>
where
    DB: Database,
{
    conn: Transaction<'static, DB>,
}

impl<DB: Database> Connect for DbTransaction<DB> {
    type DB = DB;
    type Conn<'a>
        = &'a mut DB::Connection
    where
        Self: 'a;

    async fn conn(&mut self) -> Result<Self::Conn<'_>, InternalError> {
        return Ok(&mut *self.conn);
    }
}

impl<DB: Database> DbInterface<DbTransaction<DB>> {
    pub async fn commit(self) -> Result<(), InternalError> {
        return self
            .connector
            .conn
            .commit()
            .await
            .map_err(|_| InternalError::DbError);
    }

    pub async fn rollback(self) -> Result<(), InternalError> {
        return self
            .connector
            .conn
            .rollback()
            .await
            .map_err(|_| InternalError::DbError);
    }
}

impl<C: Connect> DbInterface<C>
where
    <C::DB as Database>::Arguments: IntoArguments<C::DB>,
    for<'c> &'c mut <C::DB as Database>::Connection: Executor<'c, Database = C::DB>,
{
    pub async fn insert_one<T>(&mut self, data: T, bind_style: BindVal) -> Result<T, InternalError>
    where
        T: Bindable<C::DB> + for<'r> FromRow<'r, <C::DB as Database>::Row> + Send + Unpin,
    {
        return self
            .insert_many(&[data], bind_style)
            .await?
            .into_iter()
            .next()
            .ok_or(InternalError::NoMatches);
    }

    pub async fn insert_many<T>(
        &mut self,
        data: &[T],
        bind_style: BindVal,
    ) -> Result<Vec<T>, InternalError>
    where
        T: Bindable<C::DB> + for<'r> FromRow<'r, <C::DB as Database>::Row> + Send + Unpin,
    {
        let mut conn = self.connector.conn().await?;

        if data.is_empty() {
            let _msg = sqlx::Error::InvalidArgument("cant form a query without data".to_string());
            return Err(InternalError::DbError);
        }

        let cols = match bind_style {
            BindVal::ID => T::id_columns(),
            BindVal::BASE => T::base_columns(),
            BindVal::ALL => T::columns(),
            BindVal::ND => T::non_default_columns(),
        };
        let mut sql: QueryBuilder<C::DB> = QueryBuilder::new("INSERT INTO ");
        sql.push(T::table_name().to_string() + " (");

        let mut sepr = sql.separated(", ");
        cols.iter().for_each(|col| {
            sepr.push(col);
        });

        sql.push(") VALUES ");
        let mut is_first = true;
        for row in data {
            if is_first {
                sql.push("(");
                is_first = false;
            } else {
                sql.push(", (");
            }

            let mut sepr = sql.separated(", ");
            row.bind_values(&mut sepr, &bind_style);

            sql.push(")");
        }

        sql.push(" RETURNING *;");

        let query = sql.build_query_as::<T>();

        let res = query
            .fetch_all(&mut *conn)
            .await
            .map_err(|_| InternalError::DbError)?;

        if res.is_empty() {
            let _msg = sqlx::Error::InvalidArgument("no rows were inserted".to_string());
            return Err(InternalError::DbError);
        }

        Ok(res)
    }

    pub async fn update_one<T>(&mut self, data: T) -> Result<T, InternalError>
    where
        T: Bindable<C::DB> + for<'r> FromRow<'r, <C::DB as Database>::Row> + Send + Unpin,
    {
        let mut conn = self.connector.conn().await?;

        let mut sql: QueryBuilder<C::DB> = QueryBuilder::new("UPDATE ");
        sql.push(T::table_name()).push(" SET (");

        let mut sepr = sql.separated(", ");
        for col in T::base_columns() {
            sepr.push(col);
        }

        sql.push(") = (");

        let mut sepr = sql.separated(", ");
        data.bind_values(&mut sepr, &BindVal::BASE);

        sql.push(") WHERE (");

        let mut sepr = sql.separated(", ");
        for col in T::id_columns() {
            sepr.push(col);
        }

        sql.push(") = (");

        let mut sepr = sql.separated(", ");
        data.bind_values(&mut sepr, &BindVal::ID);

        sql.push(") RETURNING *;");

        let query = sql.build_query_as::<T>();
        let res = query
            .fetch_one(&mut *conn)
            .await
            .map_err(|_| InternalError::DbError)?;
        Ok(res)
    }

    pub async fn delete_matches<I, T>(
        &mut self,
        id_s: &[&str],
        param_s: &Vec<I>,
        op_type: LogicalOp
    ) -> Result<Vec<T>, InternalError>
    where
        Vec<I>: for<'v> Encode<'v, C::DB> + sqlx::Type<C::DB>,
        I: for<'q> Encode<'q, C::DB> + sqlx::Type<C::DB> + Copy,
        T: Bindable<C::DB> + for<'r> FromRow<'r, <C::DB as Database>::Row> + Send + Unpin,
    {
        let mut conn = self.connector.conn().await?;

        let mut sql: QueryBuilder<C::DB> = QueryBuilder::new("DELETE FROM ");
        sql.push(T::table_name())
        .push(" WHERE ");

        match op_type {
            LogicalOp::AND => {
                sql.push("(");

                let mut sepr = sql.separated(", ");
                for col in id_s {
                    sepr.push(col);
                }

                sql.push(") = (");

                let mut sepr = sql.separated(", ");
                for param in param_s {
                    sepr.push_bind(param);
                }

                sql.push(")");
            },
            LogicalOp::OR => {
                let id_param_combination = Vec::from_fn(id_s.len(), |i| (id_s[i], param_s[i]));
                let mut or_sepr = sql.separated(" OR ");

                for id_param in id_param_combination {
                    or_sepr.push(id_param.0);
                    or_sepr.push_unseparated(" = ");
                    or_sepr.push_bind_unseparated(id_param.1);
                }
            },
            LogicalOp::IN => {
                if let Some(id) = id_s.first() {
                    sql.push(format!("{id} = ANY("));
                    sql.push_bind(param_s);
                    sql.push(")");
                }
            },
        }
      
        sql.push(" RETURNING *;");

        let mut query = sql.build_query_as::<T>();

        let res = query
            .fetch_all(&mut *conn)
            .await
            .map_err(|_| InternalError::DbError)?;
        Ok(res)
    }

    pub async fn select_one<'i, I, T>(&mut self, id_s: (&[&str], &'i [I]), logic_type: LogicalOp) -> Result<T, InternalError>
    where
        I: for<'q> Encode<'q, C::DB> + sqlx::Type<C::DB> + Copy + 'i,
        &'i [I]: for<'v> Encode<'v, C::DB> + sqlx::Type<C::DB>,
        T: Bindable<C::DB> + for<'r> FromRow<'r, <C::DB as Database>::Row> + Send + Unpin,
    {
        return self
            .select_many(Some(id_s),logic_type, Some(1))
            .await?
            .into_iter()
            .next()
            .ok_or(InternalError::NoMatches);
    }

    pub async fn select_many<'i, I, T>(
        &mut self,
        id_s: Option<(&[&str], &'i [I])>,
        logic_type: LogicalOp,
        limit: Option<i32>,
    ) -> Result<Vec<T>, InternalError>
    where
        I: for<'q> Encode<'q, C::DB> + sqlx::Type<C::DB> + Copy + 'i,
        &'i [I]: for<'v> Encode<'v, C::DB> + sqlx::Type<C::DB>,
        T: Bindable<C::DB> + for<'r> FromRow<'r, <C::DB as Database>::Row> + Send + Unpin,
    {
        let mut conn = self.connector.conn().await?;

        let mut sql: QueryBuilder<C::DB> = QueryBuilder::new("SELECT * FROM ");
        sql.push(T::table_name());

        if let Some(some_id_s) = id_s {

            sql.push(" WHERE ");

            match logic_type {
                LogicalOp::AND => {
                    sql.push("(");

                    let mut sepr = sql.separated(", ");
                    for col in some_id_s.0 {
                        sepr.push(col);
                    }

                    sql.push(") = (");

                    let mut sepr = sql.separated(", ");
                    for param in some_id_s.1 {
                        sepr.push_bind(param);
                        
                    }

                    sql.push(")");
                },
                LogicalOp::OR => {
                    let id_param_combination = Vec::from_fn(some_id_s.0.len(), |i| (some_id_s.0[i], some_id_s.1[i]));
                    let mut or_sepr = sql.separated(" OR ");

                    for id_param in id_param_combination {
                        or_sepr.push(id_param.0);
                        or_sepr.push_unseparated(" = ");
                        or_sepr.push_bind_unseparated(id_param.1);
                    }
                },
                LogicalOp::IN => {
                    let id = some_id_s.0.first().ok_or(InternalError::DbError)?;

                    sql.push(id);
                    sql.push(" = ANY(");
                    sql.push_bind(some_id_s.1);
                    sql.push(")");
                },
            }


        }

        if let Some(lm) = limit {
            sql.push(" LIMIT ".to_string() + &lm.to_string());
        }

        sql.push(";");

        let res = sql
            .build_query_as::<T>()
            .fetch_all(&mut *conn)
            .await
            .map_err(|_| InternalError::DbError)?;
        Ok(res)
    }

    pub async fn generic_exec(
        &mut self,
        query: Query<'_, C::DB, <C::DB as Database>::Arguments>,
    ) -> Result<(), InternalError> {
        let mut conn = self.connector.conn().await?;
        query
            .execute(&mut *conn)
            .await
            .map_err(|_| InternalError::DbError)?;
        Ok(())
    }

    pub async fn generic_fetch<F, O, A>(
        &mut self,
        query: sqlx::query::Map<'_, C::DB, F, A>,
    ) -> Result<Vec<O>, InternalError>
    where
        F: FnMut(<C::DB as Database>::Row) -> Result<O, sqlx::Error> + Send,
        O: Send + Unpin,
        A: Send + IntoArguments<C::DB>,
    {
        let mut conn = self.connector.conn().await?;
        query
            .fetch_all(&mut *conn)
            .await
            .map_err(|_| InternalError::DbError)
    }
}
