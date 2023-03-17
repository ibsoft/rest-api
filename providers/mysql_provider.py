import pymysql
import json

class SqlToJson:
    def __init__(self, host, user, password, database):
        self.host = host
        self.user = user
        self.password = password
        self.database = database
        
    def run_query(self, query):
        try:
            # Establish a connection to the database
            conn = pymysql.connect(host=self.host,
                                   user=self.user,
                                   password=self.password,
                                   database=self.database)
            cursor = conn.cursor()
            cursor.execute(query)
            
            # Get the column names from the cursor description
            columns = [column[0] for column in cursor.description]
            
            # Fetch all results and convert to a list of dictionaries
            results = []
            for row in cursor.fetchall():
                results.append(dict(zip(columns, row)))
            
            # Convert the results to JSON
            json_results = json.dumps(results, default=str)
            
            return json_results
            
        except Exception as e:
            print(f"Error: {e}")
