import unittest

# Import all your test classes here
from test_gym_management import TestGymManagement
from test_management_auditlog import TestManagementAuditLog
from test_management_permisssion import TestManagementPermissionGroup
from test_management_role import TestManagementRole
from test_management_user import TestManagementUserAuth
from test_management_user_role import TestManagementUserRoleAssignment


def suite():
    suite = unittest.TestSuite()

    # Add all your test classes here in the desired order
    suite.addTest(unittest.makeSuite(TestGymManagement))
    suite.addTest(unittest.makeSuite(TestManagementAuditLog))
    suite.addTest(unittest.makeSuite(TestManagementPermissionGroup))
    suite.addTest(unittest.makeSuite(TestManagementRole))
    suite.addTest(unittest.makeSuite(TestManagementUserAuth))
    suite.addTest(unittest.makeSuite(TestManagementUserRoleAssignment))

    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner()
    runner.run(suite())
