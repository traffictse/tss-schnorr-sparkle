use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Replace the sample below with your own migration scripts
        // todo!();

        manager
            .create_table(
                Table::create()
                    .table(Post::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Post::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(Post::Partyfrom)
                            .integer()
                            .not_null()
                            .default(0),
                    )
                    .col(
                        ColumnDef::new(Post::Partyto)
                            .integer()
                            .not_null()
                            .default(0),
                    )
                    .col(ColumnDef::new(Post::Round).integer().not_null().default(0))
                    .col(ColumnDef::new(Post::Action).string())
                    .col(ColumnDef::new(Post::Uuid).uuid().not_null())
                    .col(ColumnDef::new(Post::Text).string().not_null())
                    .col(ColumnDef::new(Post::Timestamp).timestamp().not_null())
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx-post_party")
                    .table(Post::Table)
                    .col(Post::Partyfrom)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx-post_partyto")
                    .table(Post::Table)
                    .col(Post::Partyto)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx-post_round")
                    .table(Post::Table)
                    .col(Post::Round)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx-post_uuid")
                    .table(Post::Table)
                    .col(Post::Uuid)
                    .to_owned(),
            )
            .await?;

        Ok(()) // All good!
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Replace the sample below with your own migration scripts
        // todo!();

        manager
            .drop_index(Index::drop().name("idx-post_party").to_owned())
            .await?;
        manager
            .drop_index(Index::drop().name("idx-post_partyto").to_owned())
            .await?;

        manager
            .drop_index(Index::drop().name("idx-post_round").to_owned())
            .await?;

        manager
            .drop_index(Index::drop().name("idx-post_uuid").to_owned())
            .await?;

        manager
            .drop_table(Table::drop().table(Post::Table).to_owned())
            .await
    }
}

/// Learn more at https://docs.rs/sea-query#iden
#[derive(Iden)]
pub enum Post {
    Table,
    Id,
    Partyfrom,
    Partyto,
    Round,
    Action,
    Uuid,
    Text,
    Timestamp,
}
