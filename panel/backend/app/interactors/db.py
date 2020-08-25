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

    def create_project(self, title):
        title = self.htmlspecialchars(title)[:150]
        conn = self.get_conn()
        try:
            with conn.cursor() as cursor:
                sql = 'INSERT INTO `projects` (`title`) VALUES (%s)'
                cursor.execute(sql, title)
                sql = 'SELECT `id`, UNIX_TIMESTAMP(`start_date`) as start_date FROM `projects` WHERE `id` = LAST_INSERT_ID()'
                cursor.execute(sql)
                result = cursor.fetchone()
            conn.commit()
            return result['id'], result['start_date']
        except:
            return None, None
        finally:
            conn.close()

    def edit_project(self, pid, title):
        title = self.htmlspecialchars(title)[:150]
        conn = self.get_conn()
        try:
            with conn.cursor() as cursor:
                sql = 'UPDATE `projects` SET `title` = %s WHERE `id` = %s'
                cursor.execute(sql, (title, pid))
                state = bool(cursor.rowcount)
            conn.commit()
            return state
        except:
            return False
        finally:
            conn.close()

    def get_project_list(self):
        conn = self.get_conn()
        try:
            with conn.cursor() as cursor:
                sql = 'SELECT `id`, `title`, `is_finished`, UNIX_TIMESTAMP(`start_date`) as start_date, UNIX_TIMESTAMP(`end_date`) as end_date FROM `projects` ORDER BY `id` DESC'
                cursor.execute(sql)
                result = cursor.fetchall()
            return result
        except:
            return None
        finally:
            conn.close()

    def get_project_by_id(self, project_id):
        conn = self.get_conn()
        try:
            with conn.cursor() as cursor:
                sql = 'SELECT `id`, `title`, `is_finished`, UNIX_TIMESTAMP(`start_date`) as start_date, UNIX_TIMESTAMP(`end_date`) as end_date FROM `projects` WHERE `id` = %s'
                cursor.execute(sql, project_id)
                project_info = cursor.fetchone()
                sql = 'SELECT * FROM `attacks` WHERE `project_id` = %s'
                cursor.execute(sql, project_id)
                attacks = cursor.fetchall()
            return project_info, attacks
        except:
            return None, None
        finally:
            conn.close()

    @staticmethod
    def htmlspecialchars(text):
        return text.replace('&', '&amp;').replace('"', '&quot;').replace('<', '&lt;').replace('>', '&gt;')