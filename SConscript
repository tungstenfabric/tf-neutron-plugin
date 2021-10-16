# -*- mode: python; -*-

env = DefaultEnvironment()

setup_sources = [
    'setup.py',
    'MANIFEST.in',
    'requirements.txt',
    'test-requirements.txt',
    'tox.ini',
    '.stestr.conf',
    'neutron_plugin_contrail',
]
setup_sources_rules = [
    env.Install(Dir('.'), "#/openstack/neutron_plugin/" + file)
    for file in setup_sources
]

cd_cmd = 'cd ' + Dir('.').path + ' && '
sdist_depends = []
sdist_depends.extend(setup_sources_rules)

sdist_gen = env.Command('dist/neutron-plugin-%s.tar.gz' % env.GetPyVersion(),
                        'setup.py', cd_cmd + 'python setup.py sdist')
env.Depends(sdist_gen, sdist_depends)

test_target = env.SetupPyTestSuite(sdist_gen, use_tox=True)
env.Depends(test_target, sdist_gen)
env.Alias('openstack/neutron_plugin:test', test_target)
