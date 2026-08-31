"""
Database backend router.

Import this instead of db.py or db_elastic.py directly.
Routes to the correct backend based on DB_BACKEND in config.

Usage everywhere in the project:
    import db_router as db
    await db.init()
    results = await db.search_messages("ransomware")
"""

import config

if config.DB_BACKEND == "elasticsearch":
    from db_elastic import *  # noqa: F401,F403
else:
    from db import *  # noqa: F401,F403
