#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Vadim Lobashev 2019


import time, sys, datetime, smtplib, json
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from optparse import OptionParser
import logging
from jinja2 import Environment, FileSystemLoader


# Requests with retries
def http_session(
    retries=3,
    backoff_factor=0.3,
    status_forcelist=(500, 503, 529),
    session=None,
):
    session = session or requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session


# Getting data from Qualys SSL Labs API
def get_score(fqdn,usecache=False,maxage=0,verbose=False):
    api_url='https://api.ssllabs.com/api/v3/'
    analyze='analyze?host='+fqdn+'&publish=off&all=done'

    if usecache:
        cache = '&fromCache=on'
        if maxage != 0:
            cache += '&maxAge=' + str(maxage)
    else:
        cache = '&startNew=on'

    # Logging and sending output to stdout
    if verbose:
        sys.stdout.write('Requesting check of {} '.format(fqdn))
        sys.stdout.flush()
    logging.info('Requesting check of {} '.format(fqdn))

    # Request tooks some time, we get data from API every 10 seconds
    status = 'INITIAL'
    while status != 'READY':
        if status != 'INITIAL':
            time.sleep(10)
        try:
            get_assessment = http_session().get(api_url+analyze+cache)
            cache=''
            assessment = get_assessment.json()
            status = assessment['status']
        except KeyError:
            logging.warning(assessment['errors'][0]['message'])
            time.sleep(10)
            continue

        # Printing dots
        if verbose:
            sys.stdout.write('. ')
            sys.stdout.flush()
 
    # Logging and sending output to stdout
    if verbose:
        print(assessment['status'])
    logging.info(assessment['status'])

    # Parsing results
    results = []
    for endpoint in assessment['endpoints']:
        try:
            certs = assessment['certs']
            issuer = ''
            expires = ''
            for cert in certs:
                if endpoint['details']['certChains'][0]['certIds'][0] == cert['id']:
                    expires = datetime.datetime.utcfromtimestamp(cert['notAfter']/1000.0).strftime('%Y-%m-%d %H:%M:%S')
                    lifetime = int(cert['notAfter']/1000.0) - int(time.time())
                    issuer = cert['issuerSubject']
                else:
                    continue

            # One iteration result
            score = {
                'domain': fqdn,
                'ip': endpoint['ipAddress'], 
                'grade': endpoint['grade'], 
                'issuer': issuer, 
                'expires': expires,
                'lifetime': lifetime,
                'error': ''
            }
            
            # Logging and sending output to stdout
            if verbose:
                print('{} ({}):\n\t Grade: {}\n\t Issuer: {}\n\t Expires: {}\n\t Lifetime: {}\n\t Errors: {}'.format(score['domain'],
                    score['ip'],score['grade'],score['issuer'],score['expires'],score['lifetime'],score['error']))            
            logging.info('Domain: {}, IP: {}, Grade: {}, Issuer: {}, Expires: {}, Lifetime: {}, Errors: {}'.format(score['domain'],
                score['ip'],score['grade'],score['issuer'],score['expires'],score['lifetime'],score['error']))
            
            # Appending score to results dict
            results.append(score)
 
        # If we get errors, we return empty result
        except KeyError as error:
            logging.error('Domain: {} ({}): {}, {}'.format(fqdn,endpoint['ipAddress'], endpoint['statusMessage'], str(error)))

            score = {
                'domain': fqdn,
                'ip': endpoint['ipAddress'], 
                'grade': '', 
                'issuer': '', 
                'expires': '',
                'lifetime': '',
                'error': endpoint['statusMessage']
            }

            results.append(score)

    return results


# Save results to JSON file for any reasons
def save_results(results,filename):
    timestamp = int(time.time())
    results_dict = {
        'timestamp': timestamp,
        'results': results
    }

    logging.info('Saving results to {}.json'.format(filename))
    with open(filename, 'w') as fp:
        json.dump(results_dict, fp)


# Create plain text and HTML reports 
def create_reports(results,templates_path):

    # Formatting report in plain text
    plain_text = ''
    for result in results:
        plain_text += '{} ({})\n\tGrade: {}\n\tIssuer: {}\n\tExpires: {}\n\n'.format(result['domain'],
            result['ip'],result['grade'],result['issuer'],result['expires'])

    # We use Jinja2 templates to format report in HTML
    file_loader = FileSystemLoader(templates_path)
    env = Environment(loader=file_loader)
    template = env.get_template('mail.j2') 

    html_report = template.render(data=results)

    return plain_text,html_report


# Send report to mail
def mailsend (subject,sendby,recipients,plain_text,html_report):
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    msg = MIMEMultipart('alternative')
    
    plain_msg = MIMEText(plain_text, 'plain')
    html_msg = MIMEText(html_report, 'html')

    msg.attach(plain_msg)
    msg.attach(html_msg)

    msg['Subject'] = subject
    msg['From'] = sendby
    msg['To'] = ", ".join(recipients)

    logging.info("Sending report from {} to {}".format(sendby,", ".join(recipients)))
    s = smtplib.SMTP('localhost')
    s.sendmail(sendby, recipients, msg.as_string())
    s.quit()


# Main function
def main():

    # Options
    usage = "Usage: %prog -d example.com"
    optionparser = OptionParser(usage=usage)
    optionparser.add_option('-d', '--domain', dest='fqdn', action='store_true',
        help='Analyzing domain names (FQDN).', metavar='DOMAIN')
    optionparser.add_option('-c', '--config', dest='config',
        help='Configuration file location.', metavar='CONFIG')
    optionparser.add_option('-m', '--maxage', dest='maxage',
        help='Maximum report age, in hours, if retrieving from cache.', metavar='MAXAGE')    
    optionparser.add_option('-C', '--from-cache', dest='fromcache', action='store_true',
        help='Always deliver cached assessment reports if available.', metavar='FROMCACHE', default=None)
    optionparser.add_option('-v', '--verbose', dest='verbose', action='store_true',
        help='Verbose output.', metavar='VERBOSE', default=None)
    optionparser.add_option('-o', '--output-file', dest='outfile',
        help='Save result to file.', metavar='FILENAME', default=None)

    (options, args) = optionparser.parse_args()

    # Configure logging
    if options.config:
        with open(options.config) as config_file:
            config = json.load(config_file)
        logging.basicConfig(filename=config['logfile'],level=logging.DEBUG,
            format='%(asctime)s [%(levelname)s]: %(message)s')
    #else:
    #    logging.basicConfig(level=logging.DEBUG, format='[%(levelname)s]: %(message)s')

    # Getting SSL scores for one domain
    if options.fqdn:
        if len(args) < 1:
            optionparser.error("Incorrect number of arguments. Expected minimum 1 domain name.")

        for domain in args:
            results = get_score(domain,options.fromcache,options.maxage,options.verbose)

        if options.outfile:
            filename = options.outfile
            save_results(results,filename)

    # If we use config, we can get SSL scores for many domains
    # and send full report by e-mail
    elif options.config:
        results_full = []
        for domain in config['domains']:
            results = get_score(domain, config['cache'],config['max_age'],options.verbose)
            results_full.extend(results)
        
        if config['save_results_to_file']:
            filename = config['tmp_path'] + config['filename']
            save_results(results_full,filename)
        
        if config['sender'] == 'mail':
            plain_text,html_report = create_reports(results_full,config['templates'])
            mailsend(config['subject'],config['sendby'],config['recipients'],plain_text,html_report)
    else:
        optionparser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
