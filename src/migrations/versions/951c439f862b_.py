"""empty message

Revision ID: 951c439f862b
Revises: f7d4442b769d
Create Date: 2019-11-05 19:11:42.858479

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '951c439f862b'
down_revision = 'f7d4442b769d'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('user', sa.Column('frequency_hours', sa.Integer(), nullable=False))
    op.add_column('user', sa.Column('last_emailed', sa.DateTime(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('user', 'last_emailed')
    op.drop_column('user', 'frequency_hours')
    # ### end Alembic commands ###