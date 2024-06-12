# requests module allow us to make a request
import requests
# secure hashing
import hashlib
import sys


def request_api_data(query_char):
    # password api
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    print('res.status', res)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check the api and try again')
    return res


def get_password_leaks_count(hashes, hash_to_check):
    # split the line, separated by :
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    # hash the pwd
    # print('password.encode', password.encode('utf-8'))
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    # the response is a list of all the hashed password that share
    # the first 5 char from the passed in argument
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)
    # check if this pwd exists in API response


def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times...you should probably change your password')
        else:
            print(f'{password} was not found, carry on!')
    return 'done'


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
