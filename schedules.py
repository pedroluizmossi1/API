import schedule
import time
import math   

def seconds_to_minutes(seconds):
    minutes = seconds / 60
    return math.floor(minutes)

def minutes_to_hours(minutes):
    hours = minutes / 60
    return math.floor(hours)

def hours_to_days(hours):
    days = hours / 24
    return math.floor(days)

def seconds_to_days(seconds):
    minutes = seconds_to_minutes(seconds)
    hours = minutes_to_hours(minutes)
    days = hours_to_days(hours)
    return math.floor(days)