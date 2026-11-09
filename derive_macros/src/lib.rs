extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{self, Data, Expr, Field, Fields, Lit, Meta};

#[proc_macro_derive(Bindable, attributes(ids, include_ids))]
pub fn derive_macro_ingress(input: TokenStream) -> TokenStream {
    let parsed_vals = &syn::parse(input).expect("token parsing is expected to succeed");
    return implement_trait(parsed_vals);
}

fn is_default(field: &Field) -> bool {
    for attr in &field.attrs {
        if !attr.path().is_ident("is_default") {
            continue;
        }

        return match &attr.meta {
            // #[is_default]
            Meta::Path(_) => true,
            _ => {panic!("expected default syntax is: #[is_default]")},
        };
    }
    return false;
}

fn implement_trait(vals: &syn::DeriveInput) -> TokenStream {
    let mut ids_found: bool = false;
    let mut include_flagged: bool = false;
    let mut id_col_names: Vec<String> = vec![];

    let Data::Struct(struct_tree) = &vals.data else {
        panic!("this derive macro only supports structs");
    };

    let Fields::Named(fields) = &struct_tree.fields else {
        panic!("this derive macro only supports named fields");
    };

    let all_named_fields = fields.named.clone();

    let all_col_idents: Vec<syn::Ident> = fields.named
    .iter()
    .map(|field| field.ident.clone().expect("this derive macro only supports named fields"))
    .collect();
    
    if &vals.attrs.len() == &(0 as usize) {
        panic!("an attribute list is required");
    }

    for attrib in &vals.attrs {
        if let Meta::List(flag) = &attrib.meta && 
        flag.path.is_ident("include_ids") && 
        flag.tokens.to_string().contains("true") {
            include_flagged = true;
            continue;
        }

        if let Meta::NameValue(named) = &attrib.meta && 
        named.path.is_ident("ids") && 
        let Expr::Lit(cols_lit) = &named.value &&
        let Lit::Str(cols_str) = &cols_lit.lit
        {
            id_col_names = cols_str.value().split(";").map(String::from).collect();
            ids_found = true;
        }
    }

    if !ids_found {
        panic!("the id columns must be given");
    }

    let name = &vals.ident;
    let table_name = vals.ident.to_string().to_lowercase() + "s";

    let mut id_col_idents: Vec<syn::Ident> = vec![];
    let mut base_col_idents: Vec<syn::Ident> = vec![];
    let mut non_default_col_idents: Vec<syn::Ident> = vec![];

    let mut all_col_names: Vec<String> = vec![];
    let mut base_col_names: Vec<String> = vec![];
    let mut non_default_col_names: Vec<String> = vec![];

    for col_name in &id_col_names {
        if all_col_idents.iter().find(|col_ident| col_name.to_string() == col_ident.to_string()).is_none() {
            panic!("all given id-s must be valid field names for the struct");
        }
    }

    for col_ident in &all_col_idents {
        if id_col_names.iter().find(|id_name| id_name.to_string() == col_ident.to_string()).is_some() {
            id_col_idents.push(col_ident.clone());
            all_col_names.push(col_ident.to_string());

            if include_flagged {
                base_col_idents.push(col_ident.clone());
                base_col_names.push(col_ident.to_string());
            }
        }
        else {
            all_col_names.push(col_ident.to_string());
            base_col_idents.push(col_ident.clone());
            base_col_names.push(col_ident.to_string());
        }
    }

    for field in all_named_fields {
        if !is_default(&field) {
            non_default_col_idents.push(field.ident.clone().expect("all fields have idents"));
            non_default_col_names.push(field.ident.expect("all fields have idents").to_string());
        }
    }

    let static_ids = to_static_helper(id_col_names);
    let static_bases = to_static_helper(base_col_names);
    let static_all = to_static_helper(all_col_names);
    let static_non_default = to_static_helper(non_default_col_names);

    let bind_id = quote! { res #(.bind(&self.#id_col_idents))* };
    let bind_base = quote! { res #(.bind(&self.#base_col_idents))* };
    let bind_all = quote! { res #(.bind(&self.#all_col_idents))* };
    let bind_non_defaults = quote! { res #(.bind(&self.#non_default_col_idents))* };

    let all_col_types: Vec<&syn::Type> = fields.named.iter().map(|f| &f.ty).collect();

    let code = quote! {
        impl<DB> Bindable<DB> for #name
        where 
            DB: Database, 
            #( #all_col_types: for<'q> ::sqlx::Encode<'q, DB> + ::sqlx::Type<DB>, )*
        {
            fn table_name() -> &'static str {
                return #table_name;
            }

            fn id_columns() -> &'static [&'static str] {
                return &[#(#static_ids), *];
            }

            fn base_columns() -> &'static [&'static str] {
                return &[#(#static_bases), *];
            }

            fn columns() -> &'static [&'static str] {
                return &[#(#static_all), *];
            }
            fn non_default_columns() -> &'static [&'static str] {
                return &[#(#static_non_default), *];
            }


            fn bind_values<'lftm>(
                &'lftm self,
                query: QueryAs<'lftm, DB, Self, DB::Arguments>,
                bind_val: BindVal,
            ) -> QueryAs<'lftm, DB, Self, DB::Arguments>
            {
                let mut res = query;

                match bind_val {
                    BindVal::ID => res = #bind_id,
                    BindVal::BASE => res = #bind_base,
                    BindVal::ALL => res = #bind_all,
                    BindVal::ND => res = #bind_non_defaults,
                }

                return res;
            }
        }
    };

    return code.into();
}

fn to_static_helper(vec: Vec<String>) -> &'static [&'static str] {
    let static_chrs: Vec<&'static str> = vec.into_iter().map(|c| c.leak() as &str).collect();

    return static_chrs.leak();
}