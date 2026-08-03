from unittest import mock

from anyldap import numberalloc


def test_free_number_guesser_defaults_minimum_to_zero() -> None:
    guess = mock.Mock()

    guesser = numberalloc.freeNumberGuesser(guess)

    assert guesser.min == 0
    guess.assert_not_called()
