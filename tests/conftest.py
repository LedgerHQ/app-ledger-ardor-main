# This line includes the default `Ragger` configuration.
# It can be modified to suit local needs
from ragger.conftest import configuration

configuration.OPTIONAL.CUSTOM_SEED = "opinion change copy struggle town cigar input kit school patient execute bird bundle option canvas defense hover poverty skill donkey pottery infant sense orchard"

# This line will be interpreted by `pytest` which will load the code from the
# given modules, in this case `ragger.conftest.base_conftest`.
# This module will define several fixtures, parametrized will the fields of
# `configuration.OPTIONAL` variable.
pytest_plugins = ("ragger.conftest.base_conftest", )