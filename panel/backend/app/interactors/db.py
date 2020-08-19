import pymysql


class MySQLClient:
    def __init__(self, host, user, password, db):
        self.host = host
        self.user = user
        self.password = password
        self.db = db


    def get_conn(self):
        try:
            conn = pymysql.connect(host=self.host,
                                   user=self.user,
                                   password=self.password,
                                   db=self.db,
                                   cursorclass=pymysql.cursors.DictCursor)
        except:
            return None

        return conn

    def create_project(self, conn, title):
        title = self.htmlspecialchars(title)
        with conn.cursor() as cursor:
            sql = 'INSERT INTO `projects` (`title`) VALUES (%s)'
            cursor.execute(sql, title)
            sql = 'SELECT `id`, UNIX_TIMESTAMP(`start_date`) as start_date FROM `projects` WHERE `id` = LAST_INSERT_ID()'
            cursor.execute(sql)
            result = cursor.fetchone()
        conn.commit()
        return result['id'], result['start_date']

    def edit_project(self, conn, id, title):
        title = self.htmlspecialchars(title)
        with conn.cursor() as cursor:
            sql = 'UPDATE `projects` SET `title` = %s WHERE `id` = %s'
            cursor.execute(sql, (title, id))
            state = bool(cursor.rowcount)
        conn.commit()
        return state

    @staticmethod
    def htmlspecialchars(text):
        return text.replace('&', '&amp;').replace('"', '&quot;').replace('<', '&lt;').replace('>', '&gt;')