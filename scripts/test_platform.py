#!/usr/bin/env python3
"""Shared entry point for the platform test scripts."""

import argparse
import importlib.util
import os
import pathlib
import platform
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]


def load_runner():
	path = ROOT / 'tests/release/run.py'
	spec = importlib.util.spec_from_file_location('testd_release_checks', path)
	module = importlib.util.module_from_spec(spec)
	spec.loader.exec_module(module)
	return module


runner = load_runner()


def is_ephemeral_report(path):
	roots = [pathlib.Path(tempfile.gettempdir())]
	roots.extend(pathlib.Path(value) for name in ('TMPDIR', 'TMP', 'TEMP') if (value := os.environ.get(name)))
	if os.name != 'nt':
		roots.extend(pathlib.Path(value) for value in ('/tmp', '/run', '/dev/shm'))
	resolved = path.resolve()
	return any(resolved.is_relative_to(root.resolve()) for root in roots)


def parser_for(expected):
	label = 'macOS' if expected == 'Darwin' else expected
	parser = argparse.ArgumentParser(
		description=f'Run testd checks on {label}. Privileged and interactive suites are opt-in.',
		epilog='See tests/README.md and tests/manual/ for prerequisites, evidence, and known release blockers.',
	)
	parser.add_argument('suite', nargs='?', default='automated',
		choices=('automated', 'all', 'contracts', 'audit', 'host', 'browser', 'desktop'),
		help='automated (default), all checks, release contracts, dependency audit, host, browser, or desktop')
	parser.add_argument('--gui', action='store_true', help='include the GUI workspace (already included in all)')
	candidate = parser.add_mutually_exclusive_group()
	candidate.add_argument('--bin', type=pathlib.Path, help='existing candidate CLI; all otherwise builds one')
	candidate.add_argument('--build', action='store_true', help='build a candidate CLI (the default for all)')
	parser.add_argument('--app', type=pathlib.Path, help='candidate app or installer for desktop checks')
	parser.add_argument('--artifacts', type=pathlib.Path, help='candidate assets and checksum manifest for all')
	previous = parser.add_mutually_exclusive_group()
	previous.add_argument('--previous-bin', type=pathlib.Path, help='previous CLI for upgrade and rollback checks')
	previous.add_argument('--no-previous-release', action='store_true', help='mark prior-release checks not applicable')
	parser.add_argument('--interactive', action='store_true', help='include real browser, desktop, and manual checks')
	parser.add_argument('--plan', action='store_true', help='list all stages without running them')
	parser.add_argument('--report', type=pathlib.Path, help='new persisted report directory')
	parser.add_argument('--system', action='store_true', help='include guarded privileged and service checks')
	parser.add_argument('--port', type=int, help='browser fixture port; the following port must also be free')
	parser.add_argument('--edge-port', type=int, help='candidate HTTPS edge port for browser checks')
	parser.add_argument('--intake-port', type=int, help='candidate registration port for browser checks')
	return parser


def validate_options(parser, args):
	if args.gui and args.suite not in ('automated', 'all'):
		parser.error('--gui is only available for automated or all checks')
	if args.system and args.suite not in ('host', 'all'):
		parser.error('--system is only available for host or all checks')
	if (args.bin is not None or args.build) and args.suite not in ('host', 'browser', 'all'):
		parser.error('--bin and --build are only available for host, browser, or all checks')
	if args.app is not None and args.suite not in ('desktop', 'all'):
		parser.error('--app is only available for desktop or all checks')
	if args.suite != 'all' and (args.artifacts or args.previous_bin or args.no_previous_release or
			args.interactive or args.plan):
		parser.error('--artifacts, --previous-bin, --no-previous-release, --interactive, and --plan require all')
	if args.interactive and not args.system:
		parser.error('--interactive requires --system and a disposable, backed-up host')
	if args.suite == 'all' and args.app and not args.interactive:
		parser.error('all --app requires --interactive')
	if args.suite == 'all' and args.previous_bin and not args.artifacts:
		parser.error('--previous-bin requires --artifacts in the all suite')
	if args.suite == 'all' and args.system and not args.report and not args.plan:
		parser.error('all --system requires a new persisted --report')
	ports = (args.port, args.edge_port, args.intake_port)
	if any(port is not None for port in ports) and args.suite not in ('browser', 'all'):
		parser.error('port options are only available for browser or all checks')
	for name, port, maximum in [('port', args.port, 65534), ('edge-port', args.edge_port, 65535),
		('intake-port', args.intake_port, 65535)]:
		if port is not None and not 1 <= port <= maximum:
			parser.error(f'--{name} must be between 1 and {maximum}')
	if args.suite in ('host', 'browser') and args.bin is None and not args.build:
		parser.error(f'{args.suite} requires --bin with a candidate CLI or explicit --build')
	if args.suite == 'desktop' and args.app is None:
		parser.error('desktop requires --app with an existing candidate')
	if args.suite in ('host', 'browser', 'desktop') and args.report is None:
		parser.error(f'{args.suite} requires --report with a new persisted directory')


def candidate_path(parser, path, kind):
	candidate = path.expanduser().resolve()
	valid = candidate.exists() if kind == 'app' else candidate.is_file()
	if not valid:
		parser.error(f'{kind} candidate does not exist: {candidate}')
	return candidate


def report_path(parser, args):
	if args.report is None:
		return None
	report = args.report.expanduser().absolute()
	if report.exists() or report.is_symlink():
		parser.error(f'report path already exists: {report}')
	if (args.system or args.build or args.suite in ('desktop', 'all')) and is_ephemeral_report(report):
		parser.error(f'backups require a persisted report outside temporary directories: {report}')
	return report


def confirm_system_checks(parser):
	if not sys.stdin.isatty():
		parser.error('privileged checks require an interactive terminal and a disposable, backed-up host')
	try:
		answer = input('Confirm a disposable host with a persisted full-system snapshot; type yes: ')
	except (EOFError, KeyboardInterrupt):
		parser.error('system checks were not confirmed')
	if answer.strip().lower() != 'yes':
		parser.error('system checks were not confirmed')


def runner_arguments(parser, args):
	validate_options(parser, args)
	command = [args.suite]
	if args.gui:
		command.append('--gui')
	if args.bin is not None:
		command.extend(['--bin', str(candidate_path(parser, args.bin, 'CLI'))])
	if args.app is not None:
		command.extend(['--app', str(candidate_path(parser, args.app, 'app'))])
	if args.artifacts is not None:
		directory = args.artifacts.expanduser().resolve()
		if not directory.is_dir():
			parser.error(f'artifact directory does not exist: {directory}')
		command.extend(['--artifacts', str(directory)])
	if args.previous_bin is not None:
		command.extend(['--previous-bin', str(candidate_path(parser, args.previous_bin, 'previous CLI'))])
	if args.no_previous_release:
		command.append('--no-previous-release')
	if args.interactive:
		command.append('--interactive')
	if args.plan:
		command.append('--plan')
	report = report_path(parser, args)
	if report is not None:
		command.extend(['--report', str(report)])
	if args.system:
		if args.suite == 'host':
			confirm_system_checks(parser)
		command.append('--system')
	for name, port in [('port', args.port), ('edge-port', args.edge_port), ('intake-port', args.intake_port)]:
		if port is not None:
			command.extend([f'--{name}', str(port)])
	return command


def require_compatible_runner(parser, suite):
	required = ('main', 'automated', 'contracts', 'audit', 'native_build_target',
		'backup_build_candidate', 'candidate_build_environment')
	if suite == 'all':
		required += ('all_suites',)
	missing = [name for name in required if not callable(getattr(runner, name, None))]
	if suite == 'all' and not (ROOT / 'tests/release/all_checks.py').is_file():
		missing.append('all_checks.py')
	if missing:
		parser.error('tests/release/run.py is out of sync with these scripts; update the entire checkout '
			f'(missing: {", ".join(missing)})')


def run_cli(arguments):
	original_argv = sys.argv
	try:
		sys.argv = [original_argv[0], *arguments]
		return runner.main()
	finally:
		sys.argv = original_argv


def main(expected, arguments=None):
	parser = parser_for(expected)
	args = parser.parse_args(arguments)
	actual = platform.system()
	if actual != expected:
		label = 'macOS' if expected == 'Darwin' else expected
		parser.error(f'this script requires {label}; detected {actual}')
	require_compatible_runner(parser, args.suite)
	return run_cli(runner_arguments(parser, args))
