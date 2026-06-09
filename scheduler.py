from apscheduler.schedulers.background import (
    BackgroundScheduler
)

from config import REFRESH_INTERVAL_MINUTES

from run import main


main()

scheduler = BackgroundScheduler()

scheduler.add_job(
    main,
    "interval",
    minutes=REFRESH_INTERVAL_MINUTES,
    max_instances=1
)

scheduler.start()