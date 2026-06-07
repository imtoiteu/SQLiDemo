"""Query builder factory."""

from src.query_builder.base import QueryBuilderPort
from src.query_builder.sql_query_builder import SqlQueryBuilder


def create_query_builder() -> QueryBuilderPort:
    """Create and return a QueryBuilderPort instance.

    Returns:
        A QueryBuilderPort-compatible query builder.
    """
    return SqlQueryBuilder()
