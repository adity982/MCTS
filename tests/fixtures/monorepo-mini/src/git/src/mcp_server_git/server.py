import click


@click.command()
@click.option("--repository", required=False)
def main(repository: str | None) -> None:
    pass


def validate_repo_path(repo_path: str, allowed_repository: str | None) -> None:
    if allowed_repository is None:
        return


def git_log(repo_path: str, *args):
    import git

    repo = git.Repo(repo_path)
    return repo.git.log(*args)
