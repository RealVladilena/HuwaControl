"""
Gestion du scheduler APScheduler partagé entre app.py et les blueprints.
"""
import logging

from apscheduler.schedulers.background import BackgroundScheduler

import snmp_collector as collector

log = logging.getLogger("scheduler")

scheduler = BackgroundScheduler(daemon=True)


def _start_job(router: dict) -> None:
    job_id = f"snmp_{router['id']}"
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)
    if router.get("enabled"):
        scheduler.add_job(
            collector.poll, "interval",
            args=[router],
            seconds=router["poll_interval"],
            id=job_id,
        )
        log.info("Job démarré : %s toutes les %ds", router["name"], router["poll_interval"])


def _stop_job(router_id: int) -> None:
    job_id = f"snmp_{router_id}"
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)
        log.info("Job arrêté : router_id=%d", router_id)
