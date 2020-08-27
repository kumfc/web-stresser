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

    def has_started_projects(self):
        conn = self.get_conn()
        try:
            with conn.cursor() as cursor:
                sql = 'SELECT * FROM `projects` WHERE `is_finished` = 0'
                cursor.execute(sql)
                result = cursor.fetchone()
            return len(result) > 0
        except:
            return None
        finally:
            conn.close()

    def is_finished_project(self, project_id):
        conn = self.get_conn()
        try:
            with conn.cursor() as cursor:
                sql = 'SELECT `is_finished` FROM `projects` WHERE `id` = %s'
                cursor.execute(sql, project_id)
                result = cursor.fetchone()
            return bool(result['is_finished'])
        except:
            return None
        finally:
            conn.close()

    def finish_project(self, project_id):
        conn = self.get_conn()
        try:
            with conn.cursor() as cursor:
                sql = 'UPDATE `projects` SET `is_finished` = 1 WHERE `id` = %s'
                cursor.execute(sql, project_id)
                state = bool(cursor.rowcount)
            conn.commit()
            return state
        except:
            return False
        finally:
            conn.close()

    def get_attack_patterns(self):
        conn = self.get_conn()
        try:
            with conn.cursor() as cursor:
                sql = 'SELECT * FROM `attack_patterns`'
                cursor.execute(sql)
                result = cursor.fetchall()
            return result
        except:
            return None
        finally:
            conn.close()

    def add_attack_pattern(self, pattern):
        conn = self.get_conn()
        try:
            with conn.cursor() as cursor:
                sql = 'INSERT INTO `attack_patterns` (`attack_type`, `title`, `bin_opts`, `is_default`) VALUES (%s, %s, %s, %s)'
                cursor.execute(sql, (pattern.attack_type, pattern.title, pattern.bin_opts, pattern.is_default))
                state = bool(cursor.rowcount)
            conn.commit()
            return state
        except:
            return False
        finally:
            conn.close()

    @staticmethod
    def htmlspecialchars(text):
        return text.replace('&', '&amp;').replace('"', '&quot;').replace('<', '&lt;').replace('>', '&gt;')
