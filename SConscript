env = DefaultEnvironment().Clone()

sources = [
    'neutron_plugin_contrail',
    'requirements.txt',
    'setup.py',
    'test-requirements.txt',
    '.stestr.conf',
    'tox.ini',
    'MANIFEST.in',
]

cd_cmd = 'cd ' + Dir('.').path + ' && '
sdist_depends = []
sdist_depends.extend(setup_sources_rules)
sdist_depends.extend(local_sources_rules)
sdist_gen = env.Command('dist/contrail_neutron_plugin-0.1dev.tar.gz', 'setup.py',
                        cd_cmd + 'python setup.py sdist')
env.Depends(sdist_gen, sdist_depends)
env.Default(sdist_gen)

test_target = env.SetupPyTestSuite(
    sdist_gen,
    use_tox=True)

env.Alias('neutron_plugin_contrail:test', test_target)
