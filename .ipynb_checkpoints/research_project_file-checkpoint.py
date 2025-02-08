import pandas as pd
import numpy as np
from datetime import datetime, time
from sklearn.feature_extraction.text import TfidfVectorizer


def get_data(path):
    return pd.read_csv(path)


def find_primary_pcs(df):
    logon_df = df[df['activity'] == 'Logon']
    # Group by 'user' and 'pc', and count the occurrences
    user_pc_counts = logon_df.groupby(['user', 'pc']).size().reset_index(name='counts')
    # Find the PC with the maximum logon count for each user
    primary_pcs = user_pc_counts.loc[user_pc_counts.groupby('user')['counts'].idxmax()]
    user_pc_mapping = dict(zip(primary_pcs['user'], primary_pcs['pc']))
    return user_pc_mapping


def malicious_logon(logon_data):
    logon_data['date'] = pd.to_datetime(logon_data['date'])
    start_time = pd.to_datetime('08:00:00').time()
    end_time = pd.to_datetime('19:00:00').time()
    user_session = {}
    for _, row in logon_data.iterrows():
        user = row['user']
        if pd.isna(row['date']):
            continue
        day = row['date'].date()
        time = row['date'].time()
        activity = row['activity']
        if user not in user_session:
            user_session[user] = {}
        if day not in user_session[user]:
            user_session[user][day] = [0]
        if (time < start_time or time > end_time) and activity == 'Logon':
            user_session[user][day][0] += 1
    return user_session


def aggregate_logon_data(logon_data):
    logon_data['date'] = pd.to_datetime(logon_data['date'], format='%m/%d/%Y %H:%M:%S')

    office_start_time = time(8, 0, 0)
    office_end_time = time(19, 0, 0)

    aggregated_data = {}

    for user, user_data in logon_data.groupby('user'):
        if user not in aggregated_data:
            aggregated_data[user] = []

        for day, day_data in user_data.groupby(user_data['date'].dt.date):
            logon_times = day_data[day_data['activity'] == 'Logon']['date']
            logoff_times = day_data[day_data['activity'] == 'Logoff']['date']

            if not logon_times.empty:
                first_login = logon_times.min().time()
                last_logoff = logoff_times.max().time() if not logoff_times.empty else logon_times.max().time()
            else:
                first_login = last_logoff = None

            logins_before_office = day_data[
                (day_data['activity'] == 'Logon') & (day_data['date'].dt.time < office_start_time)]
            logins_after_office = day_data[
                (day_data['activity'] == 'Logon') & (day_data['date'].dt.time > office_end_time)]

            first_login_minutes = (datetime.combine(datetime.today(), first_login) - datetime.combine(datetime.today(),
                                                                                                      office_start_time)).total_seconds() / 60 if first_login else None
            last_logoff_minutes = (datetime.combine(datetime.today(), last_logoff) - datetime.combine(datetime.today(),
                                                                                                      office_end_time)).total_seconds() / 60 if last_logoff else None

            if not logins_before_office.empty:
                before_office_diffs = logins_before_office.apply(
                    lambda x: (datetime.combine(x['date'].date(), office_start_time) - x['date']).total_seconds() / 60,
                    axis=1
                )
                L3 = before_office_diffs.mean()
            else:
                L3 = 0

            # L4 (average difference in minutes after office hours)
            if not logins_after_office.empty:
                after_office_diffs = logins_after_office.apply(
                    lambda x: (x['date'] - datetime.combine(x['date'].date(), office_end_time)).total_seconds() / 60,
                    axis=1
                )
                L4 = after_office_diffs.mean()
            else:
                L4 = 0
            L5 = len(day_data[day_data['activity'] == 'Logon'])
            L6 = len(logins_before_office) + len(logins_after_office)
            L7 = day_data['pc'].nunique()
            L8 = logins_before_office['pc'].nunique() + logins_after_office['pc'].nunique()
            L9 = (logins_before_office['date'].diff().dropna().dt.total_seconds().sum() + logins_after_office[
                'date'].diff().dropna().dt.total_seconds().sum()) / (L6 if L6 > 0 else 1) / 60

            aggregated_data[user].append({
                'date': day,
                'diff_start_firstLogin': first_login_minutes,
                'diff_end_lastLogoff': last_logoff_minutes,
                'avg_diff_start-logon-beforeOfficeHours': L3,
                'avg_diff_end-logon-afterOfficeHours': L4,
                'no_of_logon': L5,
                'no_of_logon_outsideOfficeHours': L6,
                'no_of_computers': L7,
                'no_of_computers_outsideOfficeHours': L8,
                'avg_session_duration_outsideOfficeHours': L9
            })
    return aggregated_data


def malicious_device(user_session, device_data, user_pc):
    device_data['date'] = pd.to_datetime(device_data['date'])
    start_time = pd.to_datetime('08:00:00').time()
    end_time = pd.to_datetime('19:00:00').time()

    for _, row in device_data.iterrows():
        user = row['user']
        day = row['date'].date()
        time = row['date'].time()
        activity = row['activity']
        shared = False
        if start_time <= time <= end_time:
            continue
        if user not in user_session:
            user_session[user] = {}
        if day not in user_session[user]:
            user_session[user][day] = [0]
        if activity != 'Connect':
            continue
        if row['pc'] != user_pc[user]:
            shared = True
        session = {'time': time, 'activity': activity, 'shared': shared}
        user_session[user][day].append(session)
    return user_session


def malicious_file(user_session, file_data):
    file_data['date'] = pd.to_datetime(file_data['date'])
    start_time = pd.to_datetime('08:00:00').time()
    end_time = pd.to_datetime('19:00:00').time()

    for _, row in file_data.iterrows():
        user = row['user']
        day = row['date'].date()
        time = row['date'].time()
        filename = row['filename']
        file_type = filename.split('.')[1]
        file_type_ind = 0
        if start_time <= time <= end_time:
            continue
        if user not in user_session:
            user_session[user] = {}
        if day not in user_session[user]:
            user_session[user][day] = [0]
        if file_type == 'exe':
            file_type_ind = 1
        elif file_type == 'doc':
            file_type_ind = 2
        else:
            file_type_ind = 3
        content = row['content']
        file_size = len(content)
        count_words = content.count(' ')+1
        if file_type_ind != 0:
            session = {'time': time, 'file_type': file_type_ind, 'file_size': file_size, 'no_words': count_words}
            if day in user_session:
                user_session[user][day].append(session)
            else:
                user_session[user][day] = [0, session]
    return user_session


def malicious_email(user_pc, email, user_session):
    email['date'] = pd.to_datetime(email['date'])
    start_time = pd.to_datetime('08:00:00').time()
    end_time = pd.to_datetime('19:00:00').time()

    for _, row in email.iterrows():
        user = row['user']
        pc = row['pc']
        day = row['date'].date()
        time = row['date'].time()
        malicious = False
        if start_time <= time <= end_time:
            malicious = True
        if user_pc[user]!=pc:
            malicious = True
        if user not in user_session:
            user_session[user] = {}
        if day not in user_session[user]:
            user_session[user][day] = [0]

        outside_domain = 0
        inside_domain = 0
        no_of_attachments = row['attachments']
        size = row['size']
        organization_domain = 'dtaa.com'
        recipients =0
        to = row['to'].split(';')
        recipients += len(to)
        for i in to:
            domain = i.split('@')[1]
            if domain==organization_domain:
                inside_domain+=1
            elif domain!=organization_domain:
                outside_domain+=1

        if type(row['bcc'])==str:
            bcc = row['bcc'].split(';')
            recipients+=len(bcc)
            for i in bcc:
                domain = i.split('@')[1]
                if domain==organization_domain:
                    inside_domain+=1
                elif domain!=organization_domain:
                    outside_domain+=1

        if type(row['cc'])==str:
            cc = row['cc'].split(';')
            recipients+=len(cc)
            for i in cc:
                domain = i.split('@')[1]
                if domain==organization_domain:
                    inside_domain+=1
                elif domain!=organization_domain:
                    outside_domain+=1

        total_recipients = recipients
        session_details = {
            'emails outside organization': outside_domain,
            'emails inside organization': inside_domain,
            'total recipients': total_recipients,
            'number of attachments': no_of_attachments,
            'email_size' : size,
            'malicious': malicious
        }
        user_session[user][day].append(session_details)
    return user_session


def aggregate_email_data(user_session_email):
    aggregated_data = {}

    for user, dates_data in user_session_email.items():
        if user not in aggregated_data:
            aggregated_data[user] = []

        for date, sessions in dates_data.items():
            total_emails_outside = 0
            total_emails_inside = 0
            total_recipients = 0
            total_attachments = 0
            total_email_size = 0
            malicious_count = 0

            for session in sessions:
                if isinstance(session, dict):
                    total_emails_outside += session['emails outside organization']
                    total_emails_inside += session['emails inside organization']
                    total_recipients += session['total recipients']
                    total_attachments += session['number of attachments']
                    total_email_size += session['email_size']
                    if session['malicious']:
                        malicious_count += 1

            num_sessions = len([s for s in sessions if isinstance(s, dict)])
            average_email_size = total_email_size / num_sessions if num_sessions else 0

            aggregated_data[user].append({
                'date': date,
                'emails outside organization': total_emails_outside,
                'emails inside organization': total_emails_inside,
                'total recipients': total_recipients,
                'number of attachments': total_attachments,
                'average email size': average_email_size,
                'malicious count': malicious_count
            })

    return aggregated_data


def count_wikileaks_visits(urls):
    return sum('wikileaks.org' in url for url in urls)


def calculate_tfidf(content, vectorizer):
    if len(content) == 0:
        return 0
    tfidf_matrix = vectorizer.fit_transform(content)
    return tfidf_matrix.sum()


def malicious_http(http_data):
    tfidf_vectorizer_jobs = TfidfVectorizer()
    tfidf_vectorizer_keylogger = TfidfVectorizer()
    user_data = {}
    http_data['date'] = pd.to_datetime(http_data['date'])
    for user, user_group in http_data.groupby('user'):
        if user not in user_data:
            user_data[user] = {}

        for date, date_group in user_group.groupby(http_data['date'].dt.date):
            urls = date_group['url'].tolist()
            content = date_group['content'].tolist()

            h1 = count_wikileaks_visits(urls)
            h2 = calculate_tfidf(content, tfidf_vectorizer_jobs)
            h3 = calculate_tfidf(content, tfidf_vectorizer_keylogger)

            user_data[user][date] = {
                'wikileaks_count': h1,
                'job_search_count': h2,
                'key-logger_count': h3
            }
    return user_data


def main():
    logon_data = get_data('/Users/adithyapradeep/Documents/researchIntern_Materials/r4.2/logon.csv')

    # user_pc = find_primary_pcs(logon_data)
    # user_session_logon = malicious_logon(logon_data)
    daily_logon_data = aggregate_logon_data(logon_data)
    print(daily_logon_data)

    # device_data = get_data('/Users/adithyapradeep/Documents/researchIntern_Materials/r4.2/device.csv')
    # user_session_devices = malicious_device({}, device_data, user_pc)
s
    # file_data = get_data('/Users/adithyapradeep/Documents/researchIntern_Materials/r4.2/file.csv')
    # user_session = malicious_file(user_session, file_data)

    # email = get_data('/Users/adithyapradeep/Documents/researchIntern_Materials/r4.2/email.csv')
    # malicious cases: 1.when the recipient and the sender are from different domains.
    # 2. when the mail is sent after or before workhours.
    # data collected: the number of recipients, cc and bcc included, emails outside, emails inside, avg mail size, mal count.
    # number of emails sent outside the organization domain.
    # user_session_email = malicious_email(user_pc, email, {})
    # daily_email_data = aggregate_email_data(user_session_email)

    # http_data = get_data('/Users/adithyapradeep/Documents/researchIntern_Materials/r4.2/http.csv')
    # user_session_http = malicious_http(http_data)
    # print(user_session_http)


if __name__ == '__main__':
    main()
