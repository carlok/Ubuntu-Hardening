from pathlib import Path


PHASE2 = Path(__file__).resolve().parents[1] / "harden-phase2.sh"


def test_vim_mouse_is_released_after_ubuntu_defaults_load():
    source = PHASE2.read_text()

    assert "cat > /etc/vim/vimrc.local" in source
    assert "autocmd VimEnter * set mouse=" in source
