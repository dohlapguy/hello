"""empty message

Revision ID: f67657325db5
Revises: d97032cd0db4
Create Date: 2018-12-05 23:30:31.649654

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'f67657325db5'
down_revision = 'd97032cd0db4'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('post', sa.Column('timestamp', sa.DateTime(), nullable=True))
    op.add_column('post', sa.Column('user_id', sa.Integer(), nullable=True))
    op.alter_column('post', 'post',
               existing_type=sa.VARCHAR(),
               nullable=True)
    op.alter_column('post', 'title',
               existing_type=sa.VARCHAR(length=50),
               nullable=True)
    op.create_index(op.f('ix_post_timestamp'), 'post', ['timestamp'], unique=False)
    op.create_foreign_key(None, 'post', 'user', ['user_id'], ['id'])
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(None, 'post', type_='foreignkey')
    op.drop_index(op.f('ix_post_timestamp'), table_name='post')
    op.alter_column('post', 'title',
               existing_type=sa.VARCHAR(length=50),
               nullable=False)
    op.alter_column('post', 'post',
               existing_type=sa.VARCHAR(),
               nullable=False)
    op.drop_column('post', 'user_id')
    op.drop_column('post', 'timestamp')
    # ### end Alembic commands ###
