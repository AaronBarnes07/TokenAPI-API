import redis

domain = 'localhost'
class UserModel(object):
    def __init__(self):
        self.db = redis.Redis(domain)
        self.db_name = 'users'
        
    def get(self,key):
        user = self.db.hget(self.db_name, key)
        if user:
            return eval(user)
        return None
    
    def set(self, key, value):
        if type(value) is dict:
            value = str(value)
        return self.db.hset(self.db_name, key, value)
            
    def get_all(self):
        return self.db.hgetall(self.db_name)
    
    def keys(self):
        return self.db.hkeys(self.db_name)
    
    def delete(self):
        self.db.delete(self.db_name)
        