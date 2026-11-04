#![allow(warnings)]
use std::ops::DerefMut;

use crate::{responses::error_t::InternalError, types::*};
use sqlx::{Database, Encode, Executor, FromRow, IntoArguments, Pool, QueryBuilder, Transaction, pool::PoolConnection, query::Query};

pub trait Connect
{
    type DB: Database;
    type Conn<'a>: DerefMut<Target = <Self::DB as Database>::Connection> + Send
    where
        Self: 'a;

    async fn conn(&mut self) -> Result<Self::Conn<'_>, InternalError>;
}

#[derive(Clone)]
pub struct DbInterface<C>
where C: Connect
{
    connector: C,
}

pub struct DbPool<DB> 
where  DB: Database
{
    pool: Pool<DB>,
}

impl<DB: Database> Clone for DbPool<DB> {
    fn clone(&self) -> Self {
        return Self { pool: self.pool.clone()};
    }
}

impl<DB> Connect for DbPool<DB> 
where  DB: Database
{
    type DB = DB;
    type Conn<'a> = PoolConnection<DB>;

    async fn conn(&mut self) -> Result<Self::Conn<'_>, InternalError> {
        return Ok(self.pool.acquire().await.map_err(|_| InternalError::DbError)?);
    }
}

impl<DB: Database> DbInterface<DbPool<DB>> {

    pub async fn begin_transaction(&mut self) -> Result<DbInterface<DbTransaction<DB>>, InternalError> {
        return Ok(DbInterface { connector: DbTransaction {
            conn: self
                .connector
                .pool
                .begin()
                .await
                .map_err(|_| InternalError::DbError)?,
        } });
    }

    pub async fn new(pool: Pool<DB>) -> Result<DbInterface<DbPool<DB>>, sqlx::Error> {
        return Ok(Self {
            connector: DbPool { pool: pool },
        });
    }
}

pub struct DbTransaction<DB> 
where DB: Database
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
where <C::DB as Database>::Arguments: IntoArguments<C::DB>, 
    for<'c> &'c mut <C::DB as Database>::Connection: Executor<'c, Database = C::DB>,
{
    pub async fn insert_one<T>(&mut self, data: T, insert_all: bool) -> Result<T, InternalError>
    where T: Bindable<C::DB> + for<'r> FromRow<'r, <C::DB as Database>::Row> + Send + Unpin,
    {
        return self
            .insert_many(&[data], insert_all)
            .await?
            .into_iter()
            .next()
            .ok_or(InternalError::NoMatches);
    }

    pub async fn insert_many<T>(
        &mut self,
        data: &[T],
        insert_all: bool,
    ) -> Result<Vec<T>, InternalError>
    where
        T: Bindable<C::DB> + for<'r> FromRow<'r, <C::DB as Database>::Row> + Send + Unpin,
    {
        let mut conn = self.connector.conn().await?;

        if data.is_empty() {
            let _msg = sqlx::Error::InvalidArgument("cant form a query without data".to_string());
            return Err(InternalError::DbError);
        }
        let cols = if insert_all {
            T::columns()
        } else {
            T::base_columns()
        };
        let mut sql: QueryBuilder<C::DB> = QueryBuilder::new("INSERT INTO ");
        sql.push(T::table_name().to_string() + " (");

        let mut sepr = sql.separated(", ");
        cols.iter().for_each(|col| {
            sepr.push(col);
        });

        sql.push(") VALUES ");

        let mut sepr_outer = sql.separated(", ");
        let mut index: i32 = 1;
        for _ in 0..data.len() {
            sepr_outer.push("(");

            (0..cols.len()).for_each(|i| {
                let inp = format!("${index}");
                if i == 0 {
                    sepr_outer.push_unseparated(inp);
                } else {
                    sepr_outer.push(inp);
                }

                index += 1;
            });

            sepr_outer.push_unseparated(")");
        }

        sql.push(" RETURNING *;");

        let mut query = sql.build_query_as::<T>();
        for generic in data {
            query = generic.bind_values(query, BindVal::BASE);
        }

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
        T::base_columns().iter().for_each(|col| {
            sepr.push(col);
        });

        sql.push(") = (");

        let mut sepr = sql.separated(", ");
        ((T::id_columns().len() + 1)..=T::columns().len()).for_each(|param| {
            sepr.push(format!("${param}"));
        });

        sql.push(") WHERE (");

        let mut sepr = sql.separated(", ");
        T::id_columns().iter().for_each(|col| {
            sepr.push(col);
        });

        sql.push(") = (");

        let mut sepr = sql.separated(", ");
        (1..=T::id_columns().len()).for_each(|param| {
            sepr.push(format!("${param}"));
        });

        sql.push(") RETURNING *;");

        let query = data.bind_values(sql.build_query_as::<T>(), BindVal::ALL);
        let res = query
            .fetch_one(&mut *conn)
            .await
            .map_err(|_| InternalError::DbError)?;
        Ok(res)
    }

    pub async fn delete_many<I, T>(&mut self, id_s: &[I]) -> Result<Vec<T>, InternalError>
    where
        I: for<'q> Encode<'q, C::DB> + sqlx::Type<C::DB>,
        T: Bindable<C::DB> + for<'r> FromRow<'r, <C::DB as Database>::Row> + Send + Unpin,
    {
        let mut conn = self.connector.conn().await?;

        let mut sql: QueryBuilder<C::DB> = QueryBuilder::new("DELETE FROM ");
        sql.push(T::table_name()).push(" WHERE (");

        let mut sepr = sql.separated(", ");
        T::id_columns().iter().for_each(|col| {
            sepr.push(col);
        });

        sql.push(") = (");

        let mut sepr = sql.separated(", ");
        (1..=T::id_columns().len()).for_each(|param| {
            sepr.push(format!("${param}"));
        });

        sql.push(") RETURNING *;");

        let mut query = sql.build_query_as::<T>();
        for val in id_s {
            query = query.bind(val);
        }
        let res = query
            .fetch_all(&mut *conn)
            .await
            .map_err(|_| InternalError::DbError)?;
        Ok(res)
    }

    pub async fn select_one<I, T>(&mut self, id_s: (&[&str], &[I])) -> Result<T, InternalError>
    where
        I: for<'q> Encode<'q, C::DB> + sqlx::Type<C::DB>,
        T: Bindable<C::DB> + for<'r> FromRow<'r, <C::DB as Database>::Row> + Send + Unpin,
    {
        return self
            .select_many(Some(id_s), Some(1))
            .await?
            .into_iter()
            .next()
            .ok_or(InternalError::NoMatches);
    }

    pub async fn select_many<I, T>(
        &mut self,
        id_s: Option<(&[&str], &[I])>,
        limit: Option<i32>,
    ) -> Result<Vec<T>, InternalError>
    where
        I: for<'q> Encode<'q, C::DB> + sqlx::Type<C::DB>,
        T: Bindable<C::DB> + for<'r> FromRow<'r, <C::DB as Database>::Row> + Send + Unpin,
    {
        let mut conn = self.connector.conn().await?;

        let mut sql: QueryBuilder<C::DB> = QueryBuilder::new("SELECT * FROM ");
        sql.push(T::table_name());

        if let Some(some_id_s) = id_s {
            if some_id_s.0.len() != some_id_s.1.len() {
                let _msg = sqlx::Error::InvalidArgument(
                    "given tuple arrays have different sizes".to_string(),
                );
                return Err(InternalError::DbError);
            }

            sql.push(" WHERE (");

            let mut sepr = sql.separated(", ");
            some_id_s.0.iter().for_each(|col| {
                sepr.push(col);
            });

            sql.push(") = (");

            let mut sepr = sql.separated(", ");
            some_id_s.1.iter().for_each(|param| {
                sepr.push_bind(param);
            });

            sql.push(") ORDER BY ");

            let mut sepr = sql.separated(", ");
            for id in some_id_s.0 {
                sepr.push(T::table_name().to_string() + "." + id + " DESC");
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