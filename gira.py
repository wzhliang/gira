#!/usr/bin/env python

import giturlparse
import os
import sys
import platform
import json
import re
import urllib
import click
import subprocess
import requests
import toml
from retrying import retry
from git import Repo
from git.exc import GitCommandError
import git
from jira import JIRA


_conf = None
_version = "2020-11-10"


def _open_url(url):
    cmd = ""
    s = platform.system()
    if s == "Darwin":
        cmd = "open"
    elif s == "Windows":
        cmd = "start"
    elif s == "Linux":
        cmd = "xdg-open"
    else:
        print("Warning: f{s} is not supported yet.")
    subprocess.run([cmd, url])


class GiteeError(Exception):
    pass


class Gitee():
    api_root = "https://gitee.com/api/v5/repos/{}/{}"
    web_root = "https://www.gitee.com/"
    allowed_permissions = ("push", "pull", "admin")

    def __init__(self, user, token):
        self.user = user
        self.token = token
        # git rev-parse --show-toplevel
        # git command is not available before Repo()
        search = [".", "..", "../..", "../../..", "../../../..", "/you-will-never-find-me///"]
        for s in search:
            try:
                self.git = Git(os.path.abspath(s))
                self.owner, self.repo = self.git.info()
                break
            except git.exc.NoSuchPathError:
                raise GiteeError("You should run this from within a git repo")
            except git.exc.InvalidGitRepositoryError:
                pass # continue
        self._root = Gitee.api_root.format(self.owner, self.repo)

    def _url(self, urls, params):
        if params is not None:  # this is for GET
            params["access_token"] = self.token
            return (
                os.path.join(self._root, *urls) + "?" + urllib.parse.urlencode(params)
            )
        else:  # for PUT and POST, FIXME: this is very confusing
            return os.path.join(self._root, *urls)

    def _good_perm(self, perm):
        return perm in Gitee.allowed_permissions

    def get(self, url, params):
        return requests.get(self._url(url, params))

    def put(self, url, _data):
        d = {"access_token": self.token, "owner": self.owner, "repo": self.repo}
        d.update(_data)
        return requests.put(url, data=d)

    def patch(self, url, _data):
        d = {"access_token": self.token, "owner": self.owner, "repo": self.repo}
        d.update(_data)
        return requests.patch(url, data=d)

    def post(self, url, _data):
        d = {"access_token": self.token, "owner": self.owner, "repo": self.repo}
        d.update(_data)
        return requests.post(url, data=d)

    def delete(self, url):
        return requests.delete(url)

    def get_pr(self, pr):
        res = self.get(("pulls", pr), {})
        if not res.status_code == 200:
            raise GiteeError("RES %d" % res.status_code)
        return res.text

    def close_pr(self, pr):
        res = self.patch(self._url(("pulls", pr), None), {"state": "closed"})
        if not res.status_code == 200:
            raise GiteeError(res.text)

    def create_pr(self, title, head, body, base="master", reviewer="", tester=""):
        res = self.post(self._url(("pulls", ""), None), {
            "title": title,
            "head": head,
            "base": base,
            "body": body,
            "assignee": reviewer,
            "tester": tester,
            })
        if not res.status_code == 201:
            raise GiteeError(res)
        return res

    def get_branch(self, br):
        res = self.get(("branches", br), {})
        if not res.status_code == 200:
            raise GiteeError(res.text)
        return res

    def merge(self, pr):
        res = self.put(self._url(("pulls", pr, "merge"), None), {"number": pr})
        if not res.status_code == 200:
            raise GiteeError(res.text)

    def lock_branch(self, branch):
        res = self.put(
            self._url(("branches", branch, "protection"), None), {"branch": branch}
        )
        if not res.status_code == 200:
            raise GiteeError(res.text)

    def list_branch(self):
        res = self.get(("branches",), {})
        if not res.status_code == 200:
            raise GiteeError(res.text)
        return res

    def list_member(self):
        res = self.get(("collaborators",), {})
        if not res.status_code == 200:
            raise GiteeError(res.text)
        return res

    def list_prs(self):
        res = self.get(("pulls",), {})
        if not res.status_code == 200:
            raise GiteeError(res.text)
        return res

    def add_user(self, username, permission="push"):
        if not self._good_perm(permission):
            raise ValueError("invalid permission: {permission}")
        res = self.put(
            self._url(("collaborators", username), None), {"permission": permission}
        )
        if not res.status_code == 200:
            raise GiteeError(res.text)

    def del_user(self, username):
        res = self.delete(self._url(("collaborators", username), {}))
        if not res.status_code == 200:
            raise GiteeError(res.text)

    def print_user(self, u):
        adm = "\tadmin" if u["permissions"]["admin"] else ""
        print(f"{u['name']} ({u['login']}){adm}")

    def set_reviewer(self, assignees, testers, no_assignees=1, no_testers=1):
        res = self.put(
            self._url(("reviwer", ""), None), 
            {
                "assignees": assignees,
                "testers": testers,
                "assignees_number": no_assignees,
                "testers_number": no_testers,
            }
        )
        if not res.status_code == 200:
            raise GiteeError(res.text)
        pass

    def print_branch(self, br):
        prot = ", protected" if br["protected"] else ""
        print(f"{br['name']}{prot}")

    def print_prs(self, pr):
        print(f"{pr['number']}: {pr['title']}")

    def goto_web(self):
        url = os.path.join(Gitee.web_root, self.owner, self.repo)
        _open_url(url)

    def goto_pull(self, id=None):
        if id is None:
            url = os.path.join(Gitee.web_root, self.owner, self.repo, "pulls")
        else:
            url = os.path.join(Gitee.web_root, self.owner, self.repo, "pulls", id)
        _open_url(url)


class PR():
    def __init__(self, jsn):
        self.raw = jsn
        # TODO: handle exceptions
        self.data = json.loads(jsn)

    def good(self):
        try:
            _ = self.issue_id  # make sure it's valid
        except ValueError:
            return False
        return len(self.data["assignees"]) >= 1 and len(self.data["testers"]) >= 1

    def merged(self):
        return self.data["state"] == "merged"

    def dump(self):
        print(self.raw)

    def _get_jira_issue_id(self):
        pat = re.compile("^\s*([A-Z]*-\d*)\s+")
        mo = re.match(pat, self.title)
        if not mo:
            raise ValueError(f"Invalid PR title: {self.title}")
        return mo.group(1)

    def __getattr__(self, att):
        if att == "issue_id":
            return self._get_jira_issue_id()
        elif att == "reviwer":
            return self.data["assignees"][0]["name"]
        elif att == "tester":
            return self.data["testers"][0]["name"]

        return self.data[att]


class Git():
    def __init__(self, path="."):
        self.path = path
        self.repo = Repo(self.path)
        self.origin = self.repo.remotes["origin"].url

    def info(self):
        p = giturlparse.parse(self.origin)
        if not p.valid:
            return None, None
        return p.owner, p.repo

    """get what to cherry pick from master latest commits,
    assuming that sandbox is pulled and have the latest code"""
    def get_head_parents(self, branch="master"):
        head = self.repo.heads[branch]
        return [p.hexsha for p in head.commit.parents]

    def current_branch(self):
        return self.repo.active_branch.name

    def needs_rebase(self, head, base="master"):
        "Assume that git pull has been done"
        # intentionally not handling exception here
        # rebase logic has to be done locally so
        current = self.current_branch()
        self.repo.git.checkout(base)
        self.repo.git.checkout(current)
        bb = self.repo.merge_base(base, head)[0]  # FIXME: not sure why this is a list
        base_head = self.repo.refs[base].commit
        return bb.hexsha != base_head.hexsha

    def remote_branches(self):
        for ref in self.repo.refs:
            prefix = "refs/remotes/origin/"
            if ref.path.startswith(prefix):
                yield ref.path.partition(prefix)[2]


class ReleaseVersion():
    def __init__(self, rel):
        self.release = rel
        self.is_semver = True
        self.major = ""
        self.minor = ""
        self.fix = ""
        self.project = ""
        self._parse_release(rel)

    def _parse_release(self, rel):
        pat = re.compile("^v(\d+)\.(\d+)\.(\d+)(-[a-zA-Z0-9]+)?$")
        mobj = re.match(pat, rel)
        if not mobj:
            self.is_semver = False
            return
        self.major = mobj.group(1)
        self.minor = mobj.group(2)
        self.fix = mobj.group(3)
        self.project = mobj.group(4) or ""
        if self.project:
            self.project = self.project[1:]

    def previous(self):
        ver = f"v{self.major}.{self.minor-1}.self.fix"
        if self.project:
            ver += "-" + self.project

    def __str__(self):
        return self.release


class MyJiraError(Exception):
    pass


class MyJira():
    def __init__(self, url, user, passwd):
        self.jira = JIRA(
            _conf["jira"]["url"], auth=(_conf["jira"]["user"], _conf["jira"]["passwd"])
        )
        self.url = url

    def update_issue(self, issue_id, comment, transition):
        issue = self.jira.issue(issue_id)
        project, _ = issue_id.split("-")  # assuming format
        self.jira.add_comment(issue_id, comment)
        if transition:
            self.jira.transition_issue(issue.key, _conf[project][transition])

    def start_on_issue(self, issue_id, component, transition):
        issue = self.jira.issue(issue_id)
        issue.update(fields={"components": [{ "name": component }]})
        self.jira.transition_issue(issue.key, transition)

    def finish_issue(self, issue_id, comment):
        self.update_issue(issue_id, comment, "ready_for_test")

    def get_fix_versions(self, issue_id):
        issue = self.jira.issue(issue_id)
        return [fv.name for fv in issue.fields.fixVersions]

    def get_issue_status(self, issue_id):
        issue = self.jira.issue(issue_id)
        return issue.fields.status.name

    def get_trunk_fix_version(self, issue_id):
        fv = self.get_fix_versions(issue_id)
        for f in fv:
            rv = ReleaseVersion(f)
            if rv.fix == "0":  # '0' means trunk
                return f  # Assuming there is only one
        return None

    def get_trunk_branch(self, issue_id):
        fv = self.get_trunk_fix_version(issue_id)
        if not fv:
            return ""
        rv = ReleaseVersion(fv)
        return f"release-{rv.major}.{rv.minor}"

    def _target_br(self, fvs):
        master = False
        rv = None
        for fv in fvs:
            rv = ReleaseVersion(fv)
            if rv.fix == "0":  # '0' means trunk
                master = True
                break
        if not master:
            return f"release-{rv.major}.{rv.minor}"
        return "master"

    def get_target_branch(self, issue_id):
        "Returns PR target branch. There is bug when more than 2 fixVersions"
        return self._target_br(self.get_fix_versions(issue_id))

    def trunk_required(self, issue_id):
        return self.get_trunk_fix_version(issue_id) is not None

    def get_cherry_pick_branches(self, issue_id, ignore_trunk=True):
        fv = self.get_fix_versions(issue_id)
        branches = []
        for f in fv:
            rv = ReleaseVersion(f)
            if not rv.is_semver or rv.fix == "0":  # '0' means trunk
                continue
            rel = f"release-{rv.major}.{rv.minor}"
            if rv.project:
                rel += f"-{rv.project}"
            branches.append(rel)
        return branches

    def list_transitions(self, issue_id):
        jra = JIRA(
            _conf["jira"]["url"], auth=(_conf["jira"]["user"], _conf["jira"]["passwd"])
        )
        trs = jra.transitions(issue_id)
        for tr in trs:
            print(f"ID: {tr['id']}, Name: {tr['name']}")

    def _get_field(self, issue_id, field):
        isu = self.jira.issue(issue_id)
        return getattr(isu.fields, field)

    def get_summary(self, issue_id):
        return self._get_field(issue_id, "summary")

    def get_assignee(self, issue_id):
        assignee = self._get_field(issue_id, "assignee")
        return assignee.name if assignee is not None else ""

    def get_issue_url(self, issue_id):
        return os.path.join(self.url, "browse", issue_id)

    def push_off(self, issue_id, frm, to):
        issue = self.jira.issue(issue_id)
        newfv = []
        for fv in issue.fields.fixVersions:
            if fv.name == frm:
                newfv.append({"name": to})
            else:
                newfv.append({"name": fv.name})
        issue.update(fields={"fixVersions": newfv})

    def include(self, issue_id, version):
        issue = self.jira.issue(issue_id)
        newfv = []
        for fv in issue.fields.fixVersions:
            if fv.name == version:
                return
            newfv.append({"name": fv.name})
        newfv.append({"name": version})
        issue.update(fields={"fixVersions": newfv})

    def exclude(self, issue_id, version):
        issue = self.jira.issue(issue_id)
        newfv = []
        for fv in issue.fields.fixVersions:
            if fv.name != version:
                newfv.append({"name": fv.name})
        issue.update(fields={"fixVersions": newfv})

    def has_children(self, issue_id):
        issue = self.jira.issue(issue_id)
        return len(issue.fields.subtasks) > 0

    def is_epic(self, issue_id):
        issue = self.jira.issue(issue_id)
        return issue.fields.issuetype.name == "Epic"

    def goto_issue(self, issue_id):
        _open_url(self.get_issue_url(issue_id))


@click.group()
def main():
    pass


def _good_jira_issue(jira, issue_id, force=False):
    st = jira.get_issue_status(issue_id)
    if st in ["Resolved", "Closed"]:
        print("Jira issue {0} already Resolved or Closed. Giving up.".format(issue_id))
        return False
    vers = jira.get_fix_versions(issue_id)
    if len(vers) == 0:
        print("Invalid Jira issue: no fixVersion")
        return False
    if jira.has_children(issue_id) or jira.is_epic(issue_id):
        print("Refusing to merge issue with subtask or Epic")
        return False

    # fixVersion can be:
    # 1. x.y.0 for trunk
    # 2. x.y.z for product bug fix
    # 3. x.y.z-proj for project bug fix
    trunk = bug_fix = proj_fix = 0
    for v in vers:
        rel = ReleaseVersion(v)
        if not rel.is_semver:
            print(f"{rel} is not semver. Skipped.")
            continue
        if rel.fix == "0":  # 1
            trunk += 1
            major_rel = rel
        elif rel.project:  # 3
            proj_fix += 1
        else:  # has to be 2
            bug_fix += 1

    if trunk > 1:
        print("Jira issue assigned assigned to multiple major version. Giving up.")
        return False
    if not trunk and bug_fix and not force:
        print("Bug fixes has to go to master. Giving up.")
        return False
    if not trunk and proj_fix and not force:
        print("Bug fixes has to go to master. Giving up.")
        return False
    return True


def all_is_well(gitee, pr, jira, force):
    if not pr.good():
        print("Invalid PR. Possible causes are:")
        print("  1. PR not assigned to both reviwer and tester.")
        print("  2. PR title doesn't start with jira issue ID. e.g. CLOUD-1234")
        print("  3. PR title doesn't have summary.")
        print(f"\n{pr.html_url}")
        return False

    return _good_jira_issue(jira, pr.issue_id, force)


def cherry_pick_real(git, branches, frm, to):
    git.checkout("master")
    git.pull()
    for br in branches:
        print(f"switching to {br}...")
        git.checkout(br)
        print(f"pulling from remote repo...")
        git.pull()
        print(f"cherry picking {frm}..{to}...")
        git.cherry_pick(f"{frm}..{to}")
        print(f"pushing to remote repo...")
        git.push()
        print(f"switching to master...")
        git.checkout("master")


def cherry_pick(git, branches, frm, to, doit=True):
    """tries to automatically cherry-pick to the correct release branch from
    master"""
    if not branches:
        return
    if doit:
        cherry_pick_real(git, branches, frm, to)
        return
    print()
    print("1. Run the following commands")
    print("2. Examine the result")
    print("3. If everything looks OK, PUSH!\n")
    print("git checkout master && git pull")
    for b in branches:
        print(f"# Updating release branch {b}...")
        print(f"git checkout {b} && git pull")
        print(f"git cherry-pick {frm}..{to}")


@main.command()
@click.option(
    "--force/--no-force",
    default=False,
    help="Force merging of PR. Useful for project specific changes.",
)
@click.option(
    "--autocp/--no-autocp",
    default=True,
    help="Automatically cherry pick to various release branches",
)
@click.argument("no")
def merge(no, force, autocp):
    "Merge PR and resolve JIRA issue"
    user = _conf["gitee"]["user"]
    token = _conf["gitee"]["token"]
    try:
        gitee = Gitee(user, token)
        if gitee.git.repo.is_dirty():
            print("Working directory seems to be dirty. Refusing to continue.")
            return 1
        pr = PR(gitee.get_pr(no))
        jira = MyJira(
            _conf["jira"]["url"], _conf["jira"]["user"], _conf["jira"]["passwd"]
        )
        print(f"===> Processing PR for: {pr.issue_id} {jira.get_summary(pr.issue_id)}")
    except GiteeError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    if not all_is_well(gitee, pr, jira, force):
        return 0

    if pr.head == "master" and force:
        print("'force' only allowed for project specific bug fixes. Giving up.")
        return 4

    # used to be pr.head but there seems to be problem with gitee API
    if pr.base['label'] != "master" and jira.trunk_required(pr.issue_id):
        print("Jira fix version includes trunk but only merging to branch.")
        print("Perhaps you should split the Jira issue. Giving up.")
        print(f"\n\n\nbase: {pr.base}, issue: {pr.issue_id}")
        return 5

    try:
        if not pr.merged():
            print(f"===> Merging PR {no}...")
            gitee.merge(no)
        comment = "PR %d signed off by %s and %s.\n%s" % (
            pr.number,
            pr.reviwer,
            pr.tester,
            pr.html_url,
        )
        print(f"===> Updating jira issue status...")
        jira.update_issue(pr.issue_id, comment, "done")
        fv = jira.get_fix_versions(pr.issue_id)
        if fv:
            print(f"fixVersions: {', '.join(fv)}")
        else:
            print("Issue has no fixVersion!!!")
    except GiteeError as e:
        pr.dump()
        print(f"\n\nFailed to merge PR: {e}", file=sys.stderr)
        return 2
    # TODO: catch JIRA exception

    if force:  # FIXME: this is leaky but let's assume it's OK
        return 0

    # this has to be done to make sure that local clone has the latest commit
    try:
        print(f"===> Updating to latest master...")
        gitee.git.repo.git.checkout("master")
        gitee.git.repo.git.pull()
    except git.exc.GitCommandError as e:
        print(e)
        print("Unable to switch to master. Perhaps you have an dirty sandbox.")
        return 11

    try:
        frm, to = gitee.git.get_head_parents()
    except ValueError:
        print("Something wrong with HEAD. It's not a merge commit.")
        return 3
    # When release branch is cut early, we have to include trunk fixVersion in
    # cherry pick gargets. Like v1.100.0
    branches = jira.get_cherry_pick_branches(pr.issue_id)
    tbr = jira.get_trunk_branch(pr.issue_id)
    if tbr in gitee.git.remote_branches():
        branches.append(tbr)
    if not branches:
        return 0
    print(f"===> Cherry picking to branches: {', '.join(branches)}...")
    try:
        cherry_pick(gitee.git.repo.git, branches, frm, to, autocp)
        jira.update_issue(pr.issue_id, f"Cherry-picked to {', '.join(branches)}", "")
    except git.exc.GitCommandError as e:
        print(e)
        print("===> Something went wrong. Re-opending jira issue")
        jira.update_issue(pr.issue_id, "Cherry picking failed", "reopen")
    return 0


@main.command()
@click.argument("branch")
def lockbr(branch):
    "Lock branch"
    user = _conf["gitee"]["user"]
    token = _conf["gitee"]["token"]
    try:
        gitee = Gitee(user, token)
        gitee.lock_branch(branch)
    except Exception as e:
        print(e)


def show_branches(full):
    user = _conf["gitee"]["user"]
    token = _conf["gitee"]["token"]
    try:
        gitee = Gitee(user, token)
        res = gitee.list_branch()
        if full:
            print(res.text)
            return
        for br in json.loads(res.text):
            gitee.print_branch(br)
    except Exception as e:
        print(e)


def show_team(full):
    user = _conf["gitee"]["user"]
    token = _conf["gitee"]["token"]
    try:
        gitee = Gitee(user, token)
        res = gitee.list_member()
        if full:
            print(res.text)
            return
        for u in json.loads(res.text):
            gitee.print_user(u)
    except Exception as e:
        print(e)


def show_prs(full):
    user = _conf["gitee"]["user"]
    token = _conf["gitee"]["token"]
    try:
        gitee = Gitee(user, token)
        res = gitee.list_prs()
        if full:
            print(res.text)
            return
        for pr in json.loads(res.text):
            gitee.print_prs(pr)
    except Exception as e:
        print(e)


@main.command()
@click.option(
    "--full/--no-full",
    default=False,
    help="Display full JSON. what can be <branch, team, pr>",
)
@click.argument("what")
def show(full, what):
    "Show stuff"
    if what == "branch" or what == "branches":
        show_branches(full)
    elif what == "team":
        show_team(full)
    elif what == "pr" or what =="prs":
        show_prs(full)


@main.command()
@click.argument("user")
@click.argument("permission", default="push")
def adduser(user, permission):
    "Add gitee user"
    me = _conf["gitee"]["user"]
    token = _conf["gitee"]["token"]
    try:
        gitee = Gitee(me, token)
        gitee.add_user(user, permission)
    except Exception as e:
        print(e)


@main.command()
@click.argument("user")
def deluser(user):
    "Delete gitee user"
    me = _conf["gitee"]["user"]
    token = _conf["gitee"]["token"]
    try:
        gitee = Gitee(me, token)
        gitee.del_user(user)
    except Exception as e:
        print(e)


@main.command()
def gitee():
    "Open gitee project page"
    user = _conf["gitee"]["user"]
    token = _conf["gitee"]["token"]
    try:
        gitee = Gitee(user, token)
        gitee.goto_pull()
    except Exception as e:
        print(e)


@main.command()
@click.argument("pr_no")
def jira(pr_no):
    "Open JIRA issue page for PR"
    user = _conf["gitee"]["user"]
    token = _conf["gitee"]["token"]
    gitee = Gitee(user, token)
    jira = MyJira(
        _conf["jira"]["url"], _conf["jira"]["user"], _conf["jira"]["passwd"]
    )
    pr = PR(gitee.get_pr(pr_no))
    jira.goto_issue(pr.issue_id)


@main.command()
@click.argument("no")
def review(no):
    user = _conf["gitee"]["user"]
    token = _conf["gitee"]["token"]
    try:
        gitee = Gitee(user, token)
        pr = PR(gitee.get_pr(no))
        jira = MyJira(
            _conf["jira"]["url"], _conf["jira"]["user"], _conf["jira"]["passwd"]
        )
    except GiteeError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    print(f"===> Reviewing PR for: {pr.issue_id} {jira.get_summary(pr.issue_id)}")
    gitee.goto_pull(no)
    gitee.git.repo.git.checkout("master")
    gitee.git.repo.git.pull()
    print(f"===> Switching to branch:\t{pr.issue_id}")
    gitee.git.repo.git.checkout(pr.issue_id)
    gitee.git.repo.git.pull()
    print(f"===> Trying to run unit tests...")
    if os.system("make test") != 0:
        print(f"===> ❌ Unit tests failed!!!")
    print(f"===> Trying to build image...")
    if os.system("make docker") != 0:
        print(f"===> ❌ Building docker image failed!!!")


@main.command()
@click.argument("no")
def switch(no):
    "Switch to PR branch"
    user = _conf["gitee"]["user"]
    token = _conf["gitee"]["token"]
    try:
        gitee = Gitee(user, token)
        pr = PR(gitee.get_pr(no))
    except GiteeError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    print(f"===> Switching to branch: {pr.issue_id}")
    gitee.git.repo.git.checkout("master")
    gitee.git.repo.git.pull()
    gitee.git.repo.git.checkout(pr.issue_id)
    gitee.git.repo.git.pull()


@main.command()
@click.argument("issue_no")
def start(issue_no):
    "Start progress for JIRA issue"
    user = _conf["gitee"]["user"]
    token = _conf["gitee"]["token"]
    try:
        gitee = Gitee(user, token)
        jira = MyJira(
            _conf["jira"]["url"], _conf["jira"]["user"], _conf["jira"]["passwd"]
        )
    except MyJiraError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    def issue_ready_to_start():
        return jira.get_assignee(issue_no) and len(jira.get_fix_versions(issue_no))

    @retry(stop_max_attempt_number=10)
    def branch_ready():
        try:
            gitee.get_branch(issue_no)
            return True
        except GiteeError as e:
            raise e

    if not issue_ready_to_start():
        print("Issue has no fix versions or not assigned to someone. Aborting...")
        return False
    print("===> Updating JIRA issue status...")
    jira.update_issue(issue_no, "Starting...", "in_progress")

    print("===> Waiting for remote branch to be created...")
    # wait for webhook to create remote branch
    try:
        branch_ready()
    except GiteeError as e:
        print("Something went wrong with jira webhook. Aborting...")
        print("Possible reasons includes:")
        print("1. JIRA issue doesn't have a valid component.")
        print("2. JIRA issue isn't assigned to.")
        print("3. JIRA issue status isn't *In Progress*.")
        print("4. JIRA issue is an Epic or has subtasks.")
        print("5. 你的JIRA是中文的UI.")
        print("6. You have invalid gitee token.")

        print(e)

        return

    # checkout to new branch
    gitee.git.repo.git.checkout("master")
    gitee.git.repo.git.pull()
    print("===> Switching to PR branch...")
    gitee.git.repo.git.checkout(issue_no)
    print("\n\nYou're all set. 请开始你的表演．．．")


@main.command()
@click.argument("issue_no", nargs=-1)
def finish(issue_no):
    "Finish JIRA issue"
    user = _conf["gitee"]["user"]
    token = _conf["gitee"]["token"]
    try:
        gitee = Gitee(user, token)
        jira = MyJira(
            _conf["jira"]["url"], _conf["jira"]["user"], _conf["jira"]["passwd"]
        )
    except MyJiraError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    try:
        if gitee.git.repo.is_dirty():
            print("Working directory seems to be dirty. Refusing to continue.")
            return 2
        br = gitee.git.current_branch()
        if br == "master":
            print("You have to be on your PR branch to create a PR.")
            return 3
        print(f"===> Pushing to remote repo...")
        gitee.git.repo.git.push()

        if not issue_no:
            issue_no = gitee.git.current_branch()
        else:
            issue_no = issue_no[0]

        target_br = jira.get_target_branch(issue_no)
        if gitee.git.needs_rebase(br, target_br):
            print("!!! It looks like your branch needs rebasing.")
            return 4

        print(f"===> Creating PR for {issue_no}...")
        title = f"{issue_no} {jira.get_summary(issue_no)}"  # causes exception
        body = "%s\nFix Version/s: %s" % (
            jira.get_issue_url(issue_no), ",".join(jira.get_fix_versions(issue_no)))
        res = gitee.create_pr(title, br, body, target_br)  # TODO: automatically fill in assignee
        jira.finish_issue(issue_no, f'PR created: {res.json()["html_url"]}')
        print("===> Navigating to PR. 请手动分配reviewer和tester。并按语雀项目规定配置PR。")
        print("同时请记得将JIRA issue assign给测试人员。")
        gitee.goto_pull(str(res.json()["number"]))
    except GiteeError as e:
        print("Failed to create PR.")
        print(e)
        print(e.args[0].text)
    # TODO: catch git and jira exceptions


@main.command()
@click.argument("pr_no")
def close_pr(pr_no):
    "Close gitee PR"
    user = _conf["gitee"]["user"]
    token = _conf["gitee"]["token"]
    gitee = Gitee(user, token)
    gitee.close_pr(pr_no)


@main.command()
@click.argument("frm")
@click.argument("to")
@click.argument("issue_no")
def pushoff(issue_no, frm, to):
    try:
        jira = MyJira(
            _conf["jira"]["url"], _conf["jira"]["user"], _conf["jira"]["passwd"]
        )
        jira.push_off(issue_no, frm, to)
    except MyJiraError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


@main.command()
@click.argument("version")
@click.argument("issue_no")
def include(issue_no, version):
    "Add issue to a release"
    try:
        jira = MyJira(
            _conf["jira"]["url"], _conf["jira"]["user"], _conf["jira"]["passwd"]
        )
        print(f"Adding {issue_no} to release {version}...")
        jira.include(issue_no, version)
    except MyJiraError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

@main.command()
@click.argument("version")
@click.argument("issue_no")
def exclude(issue_no, version):
    "Remove issue from a release"
    try:
        jira = MyJira(
            _conf["jira"]["url"], _conf["jira"]["user"], _conf["jira"]["passwd"]
        )
        print(f"Removing {issue_no} from release {version}...")
        jira.exclude(issue_no, version)
    except MyJiraError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


@main.command()
@click.argument("what")
def runtests(what):
    # FIXME: don't know how to have default value for click argument
    _all = globals()
    key = f"_test_{what}"
    if key in _all:
        _all[key]()
    elif what == "all":
        _test_git()
        _test_jira()
        _test_release()
        _test_gitee()


@main.command()
def shell():
    jira = MyJira(
        _conf["jira"]["url"], _conf["jira"]["user"], _conf["jira"]["passwd"]
    )
    from ipdb import set_trace; set_trace()


@main.command()
@click.argument("issue")
def list_transitions(issue):
    jra = MyJira(_conf["jira"]["url"], _conf["jira"]["user"], _conf["jira"]["passwd"])
    jra.list_transitions(issue)


def load_conf(*names):
    global _conf
    # TODO: should validate config file
    # TODO: catch error
    for n in names:
        try:
            f = open(n)
            _conf = toml.loads(f.read())
            f.close()
        except IOError:
            continue


# {{{ Test code
def _test_jira():
    print("===> Testing jira...")
    jra = MyJira(_conf["jira"]["url"], _conf["jira"]["user"], _conf["jira"]["passwd"])
    fv = jra.get_fix_versions("CLOUD-4870")
    print(fv)
    if jra.get_summary("CLOUD-4870") != "160部署程序缺少docker load":
        print("XXX: wrong issue title")
    jra.list_transitions("TEST-4")
    jra.list_transitions("CLOUD-4414")
    st = jra.get_issue_status("CLOUD-4414")
    if st != "Closed":
        print("XXX: Wrong issue status")
    if _good_jira_issue(jra, "TEST-4"):  # No fix version
        print("XXX: Should have no fixVersion")
    if not _good_jira_issue(jra, "CLOUD-5447"):  # good fix version
        print("XXX: Should be good")
    if _good_jira_issue(jra, "CLOUD-5446"):
        print("XXX: Should not have more than one master")
    if _good_jira_issue(jra, "CLOUD-5448"):  # no trunk
        print("XXX: Should have a master release")
    if _good_jira_issue(jra, "CLOUD-5448", force=True):  # no trunk
        print("XXX: Should have a master release")
    if _good_jira_issue(jra, "CLOUD-5449"):  # project only
        print("XXX: Should have a master release")
    if not _good_jira_issue(jra, "CLOUD-5449", force=True):  # project only
        print("XXX: Should allow force merge of project only PR")
    if not _good_jira_issue(jra, "CLOUD-5450"):  # non-semver
        print("XXX: Should allow non-semver fixVersion")
    if not jra.trunk_required("CLOUD-5450"):
        print("XXX: issue requires trunk")
    if not jra.has_children("CLOUD-7356"):
        print("XXX: expected parent task")
    if not jra.is_epic("CLOUD-8443"):
        print("XXX: expected epic")
    if jra.has_children("CLOUD-7357"):
        print("XXX: expected no children task")
    if jra.get_trunk_fix_version("CLOUD-8825") != "v1.100.0":
        print("XXX: expected CLOUD-8825 to be released in v1.100.0")
    fvs = ["v1.10.0", "v1.9.1"]
    if jra._target_br(fvs) != "master":
        print("XXX: expected target branch master")
    fvs = ["v1.9.1", "v1.10.0"]
    if jra._target_br(fvs) != "master":
        print("XXX: expected target branch master")
    fvs = ["v1.9.1"]
    if jra._target_br(fvs) != "release-1.9":
        print("XXX: expected target branch release-1.9")


def _test_git():
    print("===> Testing git...")
    git = Git()
    picks = git.get_head_parents("head_parents_test")
    if len(picks) != 2:
        print("--- Something is wrong, the HEAD is not a merge commit! Perhaps you're testing in gira repo?")
    print(picks)
    git.repo.git.checkout("master")
    git.repo.git.pull()
    if git.current_branch() != "master":
        print("XXX: Current branch should be master")
    if not git.needs_rebase("rebase_test", "master"):
        print("XXX: rebase is required")
    if git.needs_rebase("release-1.1", "release-1"):
        print("XXX: rebase NOT required")
    if not "test-remote-branches" in git.remote_branches():
        print("XXX: expecting a remote branch 'test-remote-branches'")


def _test_gitee():
    print("===> Testing gitee...")
    user = _conf["gitee"]["user"]
    token = _conf["gitee"]["token"]
    gitee = Gitee(user, token)
    pr = PR(gitee.get_pr("25"))
    if pr.issue_id != "TEST-4":
        print("XXX: Should allow non-semver fixVersion")

    try:
        res = gitee.create_pr("Testing PR creation.", "create-pr-test", "lalala")
        no = res.json()["number"]
        print(f"PR {no} created.")
        gitee.close_pr(str(no))
        print(f"PR {no} closed.")
    except GiteeError as e:
        print("XXX: Failed creating PR.")
        print(e)
        print(e.args[0].text)


def _test_release():
    print("===> Testing release...")
    releases = {
        "Infinity": ("", "", "", "", False),
        "v1": ("", "", "", "", False),
        "v1.3": ("", "", "", "", False),
        "v1.3.3a": ("", "", "", "", False),
        "v1.3.3": ("1", "3", "3", "", True),
        "v1.3.3-foobar": ("1", "3", "3", "foobar", True),
    }
    for rel in releases:
        r = ReleaseVersion(rel)
        exp = releases[rel]
        if (
            r.major == exp[0]
            and r.minor == exp[1]
            and r.fix == exp[2]
            and r.project == exp[3]
            and r.is_semver == exp[4]
        ):
            print("OK")
        else:
            print(f"NOK {rel}")
            print(f"{r.major}.{r.minor}.{r.fix}-{r.project}")
# }}}


if __name__ == "__main__":
    print(f"gira {_version}\n")
    load_conf(
        os.path.join(os.environ["HOME"], "gira.toml"),
        os.path.join(os.environ["HOME"], ".config/gira.toml"),
        "gira.toml",
    )
    if _conf is None:
        print("Failed to load config file.")
        sys.exit(1)
    main()
