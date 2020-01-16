"""empty message

Revision ID: 5043ae139f5f
Revises: 9ce4d66efc8f
Create Date: 2019-12-18 16:28:43.621761

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '5043ae139f5f'
down_revision = '9ce4d66efc8f'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.alter_column('user', 'language',
               existing_type=mysql.VARCHAR(length=3),
               type_=sa.String(length=10),
               existing_nullable=True)
    op.alter_column('user', 'pref_language',
               existing_type=mysql.VARCHAR(length=3),
               type_=sa.String(length=10),
               existing_nullable=True)
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.alter_column('user', 'language',
               existing_type=sa.String(length=10),
               type_=mysql.VARCHAR(length=3),
               existing_nullable=True)
    op.alter_column('user', 'pref_language',
               existing_type=sa.String(length=10),
               type_=mysql.VARCHAR(length=3),
               existing_nullable=True)
    # ### end Alembic commands ###