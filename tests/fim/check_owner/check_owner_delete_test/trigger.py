# Delete file without check_owner option enabled.

import os

test_file = "/fim_test/check_owner_delete_test.txt"
os.remove(test_file)
