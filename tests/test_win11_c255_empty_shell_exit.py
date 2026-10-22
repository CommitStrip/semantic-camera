"""Source contract: absent backend permits shell exit, not fake normal stop."""
from pathlib import Path


SOURCE = Path(__file__).resolve().parents[1] / 'desktop/win11/MainWindow.cs'


def test_no_backend_exit_releases_shell_without_claiming_backend_stopped():
    source = SOURCE.read_text(encoding='utf-8')
    branch = source.split('case StopOutcome.NotRunning:', 1)[1].split('default:', 1)[0]
    assert '_exitRequested = true;' in branch
    assert 'DisposeNativeResources();' in branch
    assert 'Close();' in branch
    assert 'Application.Current.Shutdown();' in branch
    assert '已正常停止' not in branch


def test_incomplete_or_alive_backend_still_cannot_be_closed_by_this_fix():
    source = SOURCE.read_text(encoding='utf-8')
    block = source.split('switch (outcome)', 1)[1].split('return outcome;', 1)[0]
    rejected = block.split('case StopOutcome.IncompleteFinalization:', 1)[1]
    rejected = rejected.split('case StopOutcome.NotRunning:', 1)[0]
    assert '_exitRequested = true;' not in rejected
    assert 'Close();' not in rejected
    assert 'StopOutcome.StoppedButAlive' in rejected
    assert 'StopOutcome.StopRequestFailed' in rejected


def test_successful_exit_defers_close_until_current_closing_event_returns():
    source = SOURCE.read_text(encoding='utf-8')
    block = source.split('switch (outcome)', 1)[1].split('return outcome;', 1)[0]
    for kind in ('NormalStopped', 'NotRunning'):
        branch = block.split(f'case StopOutcome.{kind}:', 1)[1].split('break;', 1)[0]
        assert 'Dispatcher.BeginInvoke' in branch
        assert branch.index('Dispatcher.BeginInvoke') < branch.index('Close();')
