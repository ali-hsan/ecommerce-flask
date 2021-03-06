"""Initial migration.

Revision ID: a692d8cade52
Revises: 
Create Date: 2021-07-24 10:05:42.488289

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a692d8cade52'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('cartitem', sa.Column('size', sa.String(length=255), nullable=False))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('cartitem', 'size')
    # ### end Alembic commands ###
