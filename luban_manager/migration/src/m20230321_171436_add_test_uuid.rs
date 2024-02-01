use sea_orm_migration::prelude::*;

use sea_orm_migration::sea_orm::{entity::*, query::*};

use super::m20220101_000001_create_table::Post;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let insert = Query::insert()
            .into_table(Post::Table)
            .columns([Post::Action, Post::Uuid, Post::Text, Post::Timestamp])
            .values_panic([
                "keygen".into(),
                "1".into(),
                "{\"party_id\":0,\"uuid\":\"aa6da501-a0ea-4d42-be9d-99d90372b7ed\"}".into(),
                "2021-03-21T17:14:36.000Z".into(),
            ])
            .to_owned();
        manager.exec_stmt(insert).await?;

        let insert = Query::insert()
            .into_table(Post::Table)
            .columns([Post::Action, Post::Uuid, Post::Text, Post::Timestamp])
            .values_panic([
                "sign".into(),
                "1".into(),
                "{\"party_id\":0,\"uuid\":\"aa6da501-a0ea-4d42-be9d-99d90372b7ed\"}".into(),
                "2021-03-21T17:14:36.000Z".into(),
            ])
            .to_owned();
        manager.exec_stmt(insert).await?;

        let insert = Query::insert()
            .into_table(Post::Table)
            .columns([Post::Action, Post::Uuid, Post::Text, Post::Timestamp])
            .values_panic([
                "keygen".into(),
                "2".into(),
                "{\"party_id\":0,\"uuid\":\"bb6da501-a0ea-4d42-be9d-99d90372b7ed\"}".into(),
                "2021-03-21T17:14:36.000Z".into(),
            ])
            .to_owned();
        manager.exec_stmt(insert).await?;

        let insert = Query::insert()
            .into_table(Post::Table)
            .columns([Post::Action, Post::Uuid, Post::Text, Post::Timestamp])
            .values_panic([
                "sign".into(),
                "2".into(),
                "{\"party_id\":0,\"uuid\":\"bb6da501-a0ea-4d42-be9d-99d90372b7ed\"}".into(),
                "2021-03-21T17:14:36.000Z".into(),
            ])
            .to_owned();
        manager.exec_stmt(insert).await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Replace the sample below with your own migration scripts
        // todo!();
        Ok(())
    }
}
