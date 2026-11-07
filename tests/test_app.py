from pathlib import Path

from streamlit.testing.v1 import AppTest

APP = Path(__file__).resolve().parents[1] / "app.py"


def test_app_loads_demo_without_errors():
    app = AppTest.from_file(APP, default_timeout=90).run()

    assert not app.exception
    assert len(app.tabs) == 4
    assert len(app.metric) == 5
    button_labels = [button.label for button in app.button]
    assert "Dry-run" in button_labels
    assert "Approve (simulated)" in button_labels


def test_app_dry_run_is_simulated():
    app = AppTest.from_file(APP, default_timeout=90).run()
    dry_run = next(button for button in app.button if button.label == "Dry-run")
    dry_run.click().run()

    assert not app.exception
    assert "dry-run complete" in [item.value for item in app.success]


def test_app_approval_is_simulated():
    app = AppTest.from_file(APP, default_timeout=90).run()
    approve = next(button for button in app.button if button.label == "Approve (simulated)")
    approve.click().run()

    assert not app.exception
    assert "approved (simulated)" in [item.value for item in app.success]
