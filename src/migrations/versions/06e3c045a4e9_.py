"""empty message

Revision ID: 06e3c045a4e9
Revises: 25aefa751f8e
Create Date: 2019-11-05 20:17:17.334233

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '06e3c045a4e9'
down_revision = '25aefa751f8e'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('user', sa.Column('token_key', sa.String(length=255), nullable=True))
    op.add_column('user', sa.Column('token_secret', sa.String(length=255), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('user', 'token_secret')
    op.drop_column('user', 'token_key')
    # ### end Alembic commands ###
