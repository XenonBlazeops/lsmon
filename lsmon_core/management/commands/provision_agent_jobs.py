import uuid

from django.core.management.base import BaseCommand, CommandError

from lsmon_core.models import AgentProvisioningJob
from lsmon_core.provisioner import ProvisioningError, provision_job
from lsmon_core.secret_store import SecretUnavailable


class Command(BaseCommand):
    help = "Process queued agent provisioning jobs. Requires --execute in a separate privileged worker process."

    def add_arguments(self, parser):
        parser.add_argument("--execute", action="store_true")
        parser.add_argument("--limit", type=int, default=10)
        parser.add_argument("--enrollment-id", help="Process only this enrollment UUID.")

    def handle(self, *args, **options):
        if options["limit"] < 1 or options["limit"] > 100:
            raise CommandError("--limit must be between 1 and 100")
        jobs = AgentProvisioningJob.objects.filter(status=AgentProvisioningJob.Status.QUEUED).order_by("created_at")
        enrollment_id = options.get("enrollment_id")
        if enrollment_id:
            try:
                enrollment_id = uuid.UUID(enrollment_id)
            except (TypeError, ValueError) as error:
                raise CommandError("--enrollment-id must be a UUID") from error
            jobs = jobs.filter(enrollment_id=enrollment_id)
        jobs = jobs[:options["limit"]]
        if not options["execute"]:
            self.stdout.write(f"QUEUED_AGENT_PROVISIONING_JOBS={jobs.count()}")
            self.stdout.write("DRY_RUN_ONLY")
            return
        for job in jobs:
            try:
                provision_job(job)
                self.stdout.write(f"DELIVERED_JOB={job.pk}")
            except (ProvisioningError, SecretUnavailable):
                job.attempt_count += 1
                job.status = AgentProvisioningJob.Status.FAILED
                job.last_error_code = "provisioning_failed"
                job.save(update_fields=["attempt_count", "status", "last_error_code", "updated_at"])
                self.stderr.write(f"FAILED_JOB={job.pk}")
