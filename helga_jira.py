import random
import re

import requests
import smokesignal
from jira import JIRA
from requests.auth import HTTPBasicAuth
from twisted.internet import reactor

from helga import log, settings
from helga.db import db
from helga.plugins import command, match, ACKS, ResponseNotReady
from helga.util.encodings import to_unicode

logger = log.getLogger(__name__)

# These are initialized on client signon
JIRA_PATTERNS = set()


@smokesignal.on('signon')
def init_jira_patterns(*args, **kwargs):
    """
    Signal callback for IRC signon. This pulls down and caches all the stored
    JIRA ticket patterns so we don't have to do it on every message received
    """
    global JIRA_PATTERNS

    if db is None:  # pragma: no cover
        logger.warning('Cannot initialize JIRA patterns. No database connection')
        return

    JIRA_PATTERNS = set(item['re'] for item in db.jira.find())


def find_jira_numbers(message):
    """
    Finds all jira ticket numbers in a message. This will ignore any that already
    appear in a URL
    """
    global JIRA_PATTERNS

    if not JIRA_PATTERNS:
        return []

    ticket_patterns = r'({0})-[\d]+'.format('|'.join(JIRA_PATTERNS))

    # Remove URLs
    message = re.sub(r'https?://.*?{0}'.format(ticket_patterns), '', message)

    # Get the tickets, but don't be too greedy. Only allow preceeding spaces or commas
    pat = r'(^|[\s,])({0})'.format(ticket_patterns)
    print pat
    print re.findall(pat, message, re.IGNORECASE)
    tickets = [m[1] for m in re.findall(pat, message, re.IGNORECASE)]

    return tickets


def add_re(pattern):
    """
    Adds a ticket pattern from the database and local cache
    """
    global JIRA_PATTERNS

    if pattern not in JIRA_PATTERNS:
        logger.info('Adding new JIRA ticket RE: %s', pattern)
        JIRA_PATTERNS.add(pattern)
        re_doc = {'re': pattern}

        # Store in DB
        if not db.jira.find(re_doc).count():
            db.jira.insert(re_doc)
    else:  # pragma: no cover
        logger.info('JIRA ticket RE already exists: %s', pattern)

    return random.choice(ACKS)


def remove_re(pattern):
    """
    Removes a ticket pattern from the database and local cache
    """
    global JIRA_PATTERNS

    logger.info('Removing JIRA ticket RE: %s', pattern)
    JIRA_PATTERNS.discard(pattern)
    db.jira.remove({'re': pattern})

    return random.choice(ACKS)


def jira_command(client, channel, nick, message, cmd, args):
    """
    Command handler for the jira plugin
    """
    try:
        subcmd, pattern = args[:2]
    except ValueError:
        return None

    if subcmd == 'add_re':
        return add_re(pattern)

    if subcmd == 'remove_re':
        return remove_re(pattern)

    return None


def _rest_desc(ticket, url, auth=None):
    api_url = to_unicode(getattr(settings, 'JIRA_REST_API', 'http://localhost/api/{ticket}'))
    resp = requests.get(api_url.format(ticket=ticket), auth=auth, verify=False)

    try:
        resp.raise_for_status()
    except:
        logger.error('Error getting JIRA ticket %s. Status %s', ticket, resp.status_code)
        return

    try:
        return u'[{0}] {1} ({2})'.format(ticket.upper(), resp.json()['fields']['summary'], url)
    except:
        return u'[{0}] {1}'.format(ticket.upper(), url)


def jira_full_descriptions(client, channel, urls):
    """
    Meant to be run asynchronously because it uses the network
    """
    descriptions = []
    user_pass = getattr(settings, 'JIRA_AUTH', ('', ''))

    if all(user_pass):
        auth = HTTPBasicAuth(*user_pass)
    else:
        auth = None

    for ticket, url in urls.iteritems():
        desc = _rest_desc(ticket, url, auth)
        if desc is not None:
            descriptions.append(desc)

    if descriptions:
        client.msg(channel, '\n'.join(descriptions))


def jira_match(client, channel, nick, message, matches):
    jira_url = to_unicode(getattr(settings, 'JIRA_URL', 'http://localhost/{ticket}'))
    full_urls = dict((s, jira_url.format(ticket=s)) for s in matches)

    if not getattr(settings, 'JIRA_SHOW_FULL_DESCRIPTION', True):
        return u'{0} might be talking about JIRA ticket: {1}'.format(nick, ', '.join(full_urls.values()))

    # Otherwise, do the fetching with a deferred
    reactor.callLater(0, jira_full_descriptions, client, channel, full_urls)
    raise ResponseNotReady


def create_ticket(args):
    # (u'jira', [u'create', u'XXX', u'Bug', u'Help', u'Help', u"I've", u'fallen'])
    # print args
    try:
        subargs = args[1]
        new_issue = get_jira().create_issue(
            project=subargs[1],
            summary=" ".join(subargs[3:]),
            issuetype={'name': subargs[2]}
        )
        return "Ticket created : {url}/browse/{ticket_id}".format(url=jira_server, ticket_id=new_issue.key)
    except Exception as e:
        return "Failed to create ticket: {e}".format(e=e)


def assign_ticket(args):
    try:
        subargs = args[1]
        ticket_id = subargs[1]
        jira_username = subargs[2]
        get_jira().assign_issue(ticket_id, jira_username)
        return "Successfully assigned issue {ticket_id} to {jira_username}".format(
            ticket_id=ticket_id, jira_username=jira_username)
    except Exception as e:
        error = "{e}".format(e=e)
        read_data = error
        try:
            file = error.split()[len(error.split())-1]
            with open(file, 'r') as f:
                for line in f:
                    if "response text" in line:
                        read_data = line
        except:
            pass
        return "Failed to assign ticket: {data}".format(data=read_data)


def add_comment(args):
    try:
        subargs = args[1]
        ticket_id = subargs[1]
        comment = " ".join(subargs[2:])
        get_jira().add_comment(ticket_id, comment)
        return "Successfully added comment to {ticket_id}".format(ticket_id=ticket_id)
    except Exception as e:
        error = "{e}".format(e=e)
        read_data = error
        try:
            file = error.split()[len(error.split())-1]
            with open(file, 'r') as f:
                for line in f:
                    if "response text" in line:
                        read_data = line
        except:
            pass
        return "Failed to comment ticket: {data}".format(data=read_data)


@match(find_jira_numbers)
@command('jira', help="Add or remove jira ticket patterns, excluding numbers."
                      "Usage: helga jira (add_re|remove_re) <pattern>")
def jira(client, channel, nick, message, *args):
    """
    A plugin for showing URLs to JIRA ticket numbers. This is both a command to add or remove
    patterns, and a match to automatically show them. The match requires a setting JIRA_URL
    which must contain a ``{ticket}`` substring. For example, ``http://localhost/{ticket}``.

    The command takes a pattern as an argument, minus any numbers. For example, if there are JIRA
    tickets like FOOBAR-1, FOOBAR-2, and FOOBAR-3. Then you could manage the pattern via::

        helga jira add_re FOOBAR
        helga jira remove_re FOOBAR

    Ticket numbers are automatically detected.
    """

    if len(args) > 1 and len(args[1]) > 0:
        subcommand = args[1][0]
        if subcommand == 'show':
            return show_ticket(args)
        elif subcommand == "create":
            return create_ticket(args)
        elif subcommand == "assign":
            return assign_ticket(args)
        elif subcommand == "comment":
            return add_comment(args)

    if len(args) == 2:
        fn = jira_command
    else:
        fn = jira_match
    return fn(client, channel, nick, message, *args)


def show_ticket(args):
    # url, subject, assignee, status, priority
    # print "args = {}".format(args)
    ticket_id = args[1][1]
    issue = get_jira().issue(ticket_id)
    # print "{url}/browse/{ticket_id}".format(url=jira_server, ticket_id=ticket_id)
    # print issue.fields.summary
    # print issue.fields.assignee
    # print issue.fields.status

    return [
        "{url}/browse/{ticket_id}".format(url=jira_server, ticket_id=ticket_id),
        "`Summary: {0}`".format(issue.fields.summary),
        "`Assignee: {0}`".format(issue.fields.assignee),
        "`Status: {0}`".format(issue.fields.status),
        "`Priority: {0}`".format(issue.fields.priority.name),
    ]


_jira = None
jira_server = None


def get_jira():
    global _jira, jira_server
    if _jira:
        try:
            # search for an old existing issue as a cheap health check
            issue = _jira.issue('FDS-1620', fields='summary,comment')
            if issue:
                return _jira
        except:
            # pass here and assume that things are broken and recreate the _jira object
            pass

    user_pass = getattr(settings, 'JIRA_AUTH', ('', ''))
    jira_server = getattr(settings, 'JIRA_URL', 'http://localhost')
    options = {
        "verify": False
    }
    _jira = JIRA(server=jira_server, basic_auth=user_pass, options=options)
    return _jira
