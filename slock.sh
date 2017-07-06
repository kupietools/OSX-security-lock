#!/bin/bash

# OS X Security Lock BASH script, or, to its friends, "slock".
# written out of necessity by Michael E. Kupietz, https://www.kupietz.com, <kupietools@kupietz.com>.

### DISCLAIMER: Never trust the security of your computer or data to a free script written by someone else. Use of this script is entirely at your own risk. Below I describe how it works on my computer, but I make no promise at all as to what it will or won't do on yours. It could be a disaster, I don't know. If you decide to use this script despite this clear advice to the contrary, I'm not responsible for anything that happens to your computer or data as a direct or indirect result of that decision, because *I told you so*. ###
  
# This script securely locks a Macintosh computer's screen by more intelligent and secure methods than many other available options. It is designed to be run by a program like Scenario or BlueSense, to trigger it in response to unexpected external conditions (power loss, bluetooth cell phone going out of range) such as might occur in a theft. It locks more securely than a simple screen saver password because screensaver passwords allow an intruder to unlock knowing only your password, because they always display your username. This script requires a full re-login to unlock, not just your password alone, so if your Users & Groups system preference is configured not to show your username, an intruder will need to know both that and your password. 

# You can call this with a descriptive argument (like "power disabled", "computer woke up", whatever you want) to have the logs record the argument. This way you can keep a record of what triggered it. 

# It can optionally be configured to give you several seconds to enter a password to prevent locking, and/or not to run more frequently than once in a user-configurable number of seconds, in case of false positives such as those which BlueSense annoyingingly generates when it suddenly decides it can't see your phone sitting right next to your laptop, or when ControlPlane crashes and restarts over and over and over and over and over and over and over again. It operates by a failsafe - locking is initiated before the password dialog is presented, and only entering the correct password aborts the lock. Any other condition allows the locking to continue. 

# Tested working on MacOS X Sierra 10.12.4

### SPECIFY GLOBAL BEHAVIOR SETTINGS ###

thePassword="password"
# Think quick! If alwaysOfferChanceToEnterPassword and/or giveDelayToEnterPasswordOnNetworks is enabled below, the above password can be entered to prevent the screen from locking. This is to prevent the occasional annoying false positive while I'm in the middle of working, or to allow bypassing the lock when first waking the computer up.

thePasswordDelay=10
# Delay (in seconds) before locking the computer, to give the user an opportunity to enter a password to bypass. Note: Make this short enough that a potential thief doesn't have time to drop into Terminal, run a 'ps', get the name of this script, and abort it before locking! I recommend a 5 second default. Maybe 10 at most, if you're a slow typer and need it.

alwaysOfferChanceToEnterPassword='true'
# Set to 'true' to always offer 5 seconds to enter password before locking. Not setting to true uses giveDelayToEnterPasswordOnNetworks below to decide which networks to pop up the password dialog on. I'm quoting 'true' to avoid BASH's ordinarily confusing use of the value true (without quotes).

dontRunMoreOftenThan=30
# I don't want it running more than once every 30 seconds, sometimes the processes that trigger it run wild or crash and retrigger repeatedly. (I'm looking at you, ControlPlane.)

### SPECIFY BEHAVIOR BY SPECIFIC NETWORK SSIDs ###

doNotTriggerOnNetworks='Home_Network_SSID|OfficeNetwork|FortKnoxGuest|ShipwreckSurvivorFreeWifi'
#Security lock will never trip when above networks are connected. Useful to automatically turn this off when in trusted places where you feel your computer is not in danger of being stolen or infiltrated, such as your home, office, Fort Knox, or on a desert island where you're the only person for thousands of miles. 

giveDelayToEnterPasswordOnNetworks='TheCafeIAlwaysGoto_Wifi'
#Enter frequently used networks above. When connected to one of these networks, this script will give 5 second delay to enter password to abort security lock. This is intended as a 'medium security' setting, to give you a chance to abort locking in places that you frequently work but which you still want to protect against your data being vulnerable if your laptop gets snatched. This does nothing if alwaysOfferChanceToEnterPassword is set to true.

### LOG SETUP ###

logLocation=~/Library/Logs/mkSecurity.log
#specify a location for logging. Very helpful for figuring out what happened if there's a misfire.

#First check how recently this ran, abort if too soon. 

thatTime=$(cat /var/tmp/lockscreen.sh.tmp)   
thisTime=`date +%s`
theDiff=$thisTime-$thatTime
if [ $theDiff -lt $dontRunMoreOftenThan ] 
then
    echo $(date '+%Y-%m-%d %H:%M:%S') slock trigger $1, too darn soon! Killing, not suspending. This: $thisTime, Last: $thatTime, diff: $theDiff >> $logLocation
    exit 1
fi
echo `date +%s` > /var/tmp/lockscreen.sh.tmp
echo $(date '+%Y-%m-%d %H:%M:%S') slock trigger $1, passed time check. This: $thisTime, Last: $thatTime, diff: $theDiff >> $logLocation

# Commencing countdown, engines on

theSSID=`/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I | awk '/ SSID/ {print substr($0, index($0, $2))}'`
# Get the SSID of the currently connected wifi network

thisUser=`id -u`
# Get the current userid

theLoginStatusJSON=`python -c 'import objc;from Foundation import NSBundle;CG_bundle = NSBundle.bundleWithIdentifier_("com.apple.CoreGraphics");functions = [("CGSSessionCopyAllSessionProperties", b"@"),];objc.loadBundleFunctions(CG_bundle, globals(), functions);graphical_security_sessions = CGSSessionCopyAllSessionProperties();print graphical_security_sessions'`
# Get the current session status - we'll use this to prevent running if session is already locked (multiple triggers can fire one after another, causing painful immediate consecutive locking, and high-volume user invective)

theRegex="kCGSSessionOnConsoleKey = 0[^}]*kCGSSessionUserIDKey = $thisUser"
# Create regex that, if $theLoginStatusJSON matches, means screen is currently locked.

if [[ $doNotTriggerOnNetworks =~ $theSSID || $theLoginStatusJSON =~ $theRegex ]]  
# Conditional #1: Are we on a home network, OR, is the screen already locked?
then
    # Result 1A: we're on home network OR screen already locked, skip security measures, just log that this ran and do nothing else.
    # Let's put together the log message:
    theReason=""
    if [[ $doNotTriggerOnNetworks =~ $theSSID ]]  
    then
  	    theReason=" on home network"
    fi
    if [[ $doNotTriggerOnNetworks =~ $theSSID && $theLoginStatusJSON =~ $theRegex ]] 
    then
        theReason="$theReason AND"
    fi 
    if [[  $theLoginStatusJSON =~ $theRegex ]] 
    then 
        theReason="$theReason screen already locked"
    fi
    # Ok, $theReason is ready to be recorded in the log.

    echo $(date '+%Y-%m-%d %H:%M:%S') slock trigger $1 triggered - $theReason, not halting >> $logLocation

else
# Result 1B: We're not on home network

    if [[ $giveDelayToEnterPasswordOnNetworks =~ $theSSID || $alwaysOfferChanceToEnterPassword == 'true' ]]
    # Conditional #2: Are we on a familiar SSID, or, is it set to always display dialog?

    then
    # Result 2: We're on a familiar network, or it's set to always allow a password to abort lock. Give user a chance to enter password to avoid locking.
    
        echo $(date '+%Y-%m-%d %H:%M:%S') slock trigger $1 triggered - requiring password $thePasswordDelay sec >> $logLocation
        # Launch a background process that gives 5 seconds to enter a password, and kills the screen locking process if the password is correct:
    
        (
        # the background process starts here
    
            theAnswer=`osascript -e 'tell me to activate' -e 'set theAnswer to the text returned of (display dialog "You have '"$thePasswordDelay"' seconds to enter the  password." default answer "" buttons {"OK"} default button 1 giving up after '"$thePasswordDelay"' with hidden answer)'`
            # Beware, mortals: osascript -e 'blah "blah" $varName blah' would be nice, but $varName doesn't evaluate within single quotes and the command fails. You need to either use the funky syntax 'blah "blah" '"$varName"' blah", or use "blah \"blah\" $varName blah". I've opted for the first because I'm less familiar with it and want to remember it.
        
            if [[ $theAnswer == $thePassword ]] 
            then
            # Correct password entered
        
                echo $(date '+%Y-%m-%d %H:%M:%S') slock trigger $1 stopped by correct password >> $logLocation
                # From here (still in the background process) we kill this whole script, which is already running independently in the foreground and counting down to locking the machine: 
        
                thisScript=`basename "$0"`
                # set $thisScript to the name of this running bash script
        
                forGrep="[${thisScript:0:1}]${thisScript:1}"
                # if we don't convert "ThisScriptName.sh" to "[T]hisScriptName.sh", the following ps command will return an extra row for the grep statement itself. With the brackets it matches the script's actual name but not the grep command process.
        
                ps -ef | grep "$forGrep" | awk '{print $2}' | xargs kill -9
                # Killed. We use quotes in the grep expression in case of spaces in this file's name.
        
            fi
            echo $(date '+%Y-%m-%d %H:%M:%S') slock trigger $1 triggered - Dialog timed out with answer "$theAnswer", trigger not stopped  >> $logLocation    
        ) &
         # And that's the end of the commands being launched in a background process
        
        echo $(date '+%Y-%m-%d %H:%M:%S') slock trigger $1 triggered - about to pause for $thePasswordDelay before halting >> $logLocation
    
        # Independently of the background process, in the foreground, begin a countdown before locking, to give user time to enter the password into the dialog being presented by the above background process.
        sleep $thePasswordDelay
        
        # End of result #2

    fi
    # End Conditional #2

    echo $(date '+%Y-%m-%d %H:%M:%S') slock trigger $1 triggered - about to suspend user session >> $logLocation
    # Now lock the session. Doing it this way prevents the user list from displaying if the login screen is set not to display username, requiring it to be typed in, which is much more secure than giving away half the authentication requirements. (Simply locking via the screensaver is easier, but would alway give away the username by displaying it, which is less secure.)

    /System/Library/CoreServices/Menu\ Extras/User.menu/Contents/Resources/CGSession -suspend
    echo $(date '+%Y-%m-%d %H:%M:%S') slock trigger $1 triggered - user session suspended >> $logLocation
    # And, we're locked.
    # end of result #1B

fi
# End Conditional #1
