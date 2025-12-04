"""
Tests for the Pipeline orchestrator.

Tests pipeline stages, resume functionality, and authorization checks.
"""

from pathlib import Path

import pytest

from recon_bounty_stack.core.config import Config
from recon_bounty_stack.core.pipeline import Pipeline, PipelineStage


class TestPipelineStage:
    """Tests for PipelineStage class."""

    def test_stage_creation(self):
        """Test creating a pipeline stage."""
        stage = PipelineStage("test", "Test Stage")
        assert stage.name == "test"
        assert stage.description == "Test Stage"
        assert not stage.completed
        assert stage.duration == 0.0

    def test_stage_duration(self):
        """Test stage duration calculation."""
        from datetime import datetime, timedelta

        stage = PipelineStage("test", "Test Stage")
        stage.start_time = datetime.now()
        stage.end_time = stage.start_time + timedelta(seconds=30)
        assert stage.duration == pytest.approx(30.0, abs=0.1)


class TestPipeline:
    """Tests for Pipeline class."""

    def test_pipeline_creation(self, config: Config):
        """Test creating a pipeline."""
        pipeline = Pipeline(config=config)
        assert pipeline.config == config
        assert not pipeline.dry_run
        assert len(pipeline.stages) == 5

    def test_pipeline_dry_run(self, config: Config):
        """Test pipeline in dry-run mode."""
        pipeline = Pipeline(config=config, dry_run=True)
        assert pipeline.dry_run

    def test_pipeline_stages(self, config: Config):
        """Test pipeline has all required stages."""
        pipeline = Pipeline(config=config)
        stage_names = [s.name for s in pipeline.stages]
        assert "recon" in stage_names
        assert "httpx" in stage_names
        assert "nuclei" in stage_names
        assert "triage" in stage_names
        assert "report" in stage_names

    def test_status(self, config: Config):
        """Test getting pipeline status."""
        config.ensure_directories()
        pipeline = Pipeline(config=config)
        status = pipeline.status()

        assert "stages" in status
        assert "summary" in status
        assert len(status["stages"]) == 5

    def test_reset(self, config: Config):
        """Test resetting pipeline status."""
        config.ensure_directories()
        pipeline = Pipeline(config=config)

        # Create status file
        status_file = config.output_dir / ".pipeline_status"
        status_file.write_text("recon\nhttpx\n")
        assert status_file.exists()

        # Reset
        pipeline.reset()
        assert not status_file.exists()

    def test_authorization_check(self, config: Config, sample_targets: list[str]):
        """Test authorization check functionality."""
        config.ensure_directories()
        pipeline = Pipeline(config=config)

        # Without authorization, targets should fail
        authorized, unauthorized = pipeline.check_authorization(sample_targets)
        assert not authorized
        assert len(unauthorized) == len(sample_targets)

    def test_dry_run_execution(
        self, config: Config, sample_targets: list[str], valid_authorization: Path
    ):
        """Test dry run execution."""
        config.auth_dir = valid_authorization.parent
        config.ensure_directories()
        pipeline = Pipeline(config=config, dry_run=True)

        results = pipeline.run(
            targets=["example.com"],
            skip_auth=False,
        )

        assert "stages" in results
        assert "summary" in results
        # In dry run, stages should show dry_run: True
        for _stage_name, stage_data in results["stages"].items():
            if stage_data.get("results"):
                assert stage_data["results"].get("dry_run") is True

    def test_mark_complete(self, config: Config):
        """Test marking stages as complete."""
        config.ensure_directories()
        pipeline = Pipeline(config=config)

        # Mark a stage complete
        pipeline._mark_complete("recon")

        # Check it was recorded
        completed = pipeline._load_status()
        assert "recon" in completed

    def test_load_status_empty(self, config: Config):
        """Test loading status when no status file exists."""
        config.ensure_directories()
        pipeline = Pipeline(config=config)

        completed = pipeline._load_status()
        assert completed == set()
