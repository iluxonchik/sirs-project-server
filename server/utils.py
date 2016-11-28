"""
Utility classes.
"""

class Duration(object):
    MINUTE = 60  # a minute is 60 seconds
    HOUR = MINUTE * 60  # an hour is 60 minutes
    DAY = HOUR * 24  # a day is 24 hours
    
    @classmethod
    def minutes(cls, seconds):
        return seconds * cls.MINUTE
    
    @classmethod
    def hours(cls, seconds):
        return seconds * cls.HOUR

    @classmethod
    def days(cls, seconds):
        return seconds * cls.DAY


