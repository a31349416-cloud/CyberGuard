"""init scans with user_id and owasp_map"""
from alembic import op
import sqlalchemy as sa

revision = "001"
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    # SQLite/PostgreSQL сумісно
    op.create_table(
        "scans",
        sa.Column("scan_id", sa.String(), primary_key=True),
        sa.Column("url", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("risk_score", sa.Integer(), server_default="0"),
        sa.Column("level", sa.String(), server_default="LOW"),
        sa.Column("findings", sa.Text(), server_default="[]"),
        sa.Column("scanners", sa.Text(), server_default="[]"),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("completed_at", sa.String(), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("user_id", sa.String(), server_default="anonymous"),
        sa.Column("owasp_map", sa.Text(), server_default="{}"),
    )
    op.create_index("idx_scans_created", "scans", ["created_at"])
    op.create_index("idx_scans_user", "scans", ["user_id"])
    # users table for auth
    op.create_table(
        "users",
        sa.Column("username", sa.String(), primary_key=True),
        sa.Column("pwd_hash", sa.String(), nullable=False),
        sa.Column("role", sa.String(), server_default="user"),
        sa.Column("created_at", sa.String(), nullable=False),
    )

def downgrade():
    op.drop_index("idx_scans_user", table_name="scans")
    op.drop_index("idx_scans_created", table_name="scans")
    op.drop_table("scans")
    op.drop_table("users")
