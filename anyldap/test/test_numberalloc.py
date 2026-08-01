from anyldap import numberalloc


def test_free_number_guesser_defaults_minimum_to_zero():
    guesser = numberalloc.freeNumberGuesser(lambda value: None)
    assert guesser.min == 0
