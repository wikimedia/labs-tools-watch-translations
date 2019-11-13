"""empty message

Revision ID: 78934e2cc19d
Revises: 951c439f862b
Create Date: 2019-11-05 20:13:07.699418

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '78934e2cc19d'
down_revision = '951c439f862b'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('user', sa.Column('email', sa.String(length=255), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('user', 'email')
    # ### end Alembic commands ###