"""
pyencryption base module.

This is the principal module of the pyencryption project.
here you put your main classes and objects.

Be creative! do whatever you want!
"""


class BaseClass:
    def base_method(self) -> str:
        """
        Base method.
        """
        return "hello from BaseClass"

    def __call__(self) -> str:
        return self.base_method()


def base_function() -> str:
    """
    Base function.
    """
    return "hello from base function"
