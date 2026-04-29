import datetime


def utcnow() -> datetime.datetime:
    """Naive UTC datetime; matches the project's SQLAlchemy DateTime columns
    and all existing datetime comparisons (which assume tz-naive)."""
    return datetime.datetime.now(datetime.UTC).replace(tzinfo=None)
