from django.db import models
from django.conf import settings
from django.contrib.auth.hashers import make_password
from django.utils.crypto import get_random_string
from django.utils.translation import ugettext_lazy as _

from django_auth_policy.settings import (TEMP_PASSWORD_LENGTH,
                                         TEMP_PASSWORD_CHARS)


class LoginAttemptManager(models.Manager):
    def unlock(self, usernames=[], addresses=[]):
        """ Unlocks given usernames and IP addresses

        Returns the number of attempts that have been unlocked.
        """
        if not usernames and not addresses:
            return 0

        selection = models.Q()

        if usernames:
            selection |= models.Q(username__in=set(usernames))

        if addresses:
            selection |= models.Q(source_address__in=set(addresses))

        return self.get_queryset().filter(
            selection, lockout=True).update(lockout=False)

    def unlock_queryset(self, queryset):
        """ Unlocks all usernames and IP addresses found in ``queryset``

        Returns the number of attempts that have been unlocked.
        """
        selected_attempts = queryset.filter(
            lockout=True).order_by().values_list('username', 'source_address')

        if not selected_attempts:
            return 0

        usernames, addresses = zip(*selected_attempts)

        return self.unlock(usernames=usernames, addresses=addresses)


class LoginAttempt(models.Model):
    # Username tried to log in
    username = models.CharField(_('username'), max_length=100, db_index=True)
    source_address = models.GenericIPAddressField(
        _('source address'), protocol='both', db_index=True)
    hostname = models.CharField(_('hostname'), max_length=100)
    successful = models.BooleanField(_('successful'), default=False)
    timestamp = models.DateTimeField(_('timestamp'), auto_now_add=True,
                                     db_index=True)
    # User fields are only filled at successful login attempts:
    user = models.ForeignKey(settings.AUTH_USER_MODEL, verbose_name=_('user'),
                             blank=True, null=True, on_delete=models.SET_NULL)
    user_repr = models.CharField(_('user'), blank=True, max_length=200)
    # This is enabled for all failed login attempts. It is reset for every
    # successful login and can be reset by 'user admins'.
    lockout = models.BooleanField(_('lockout'), default=True,
                                  help_text=_('Counts towards lockout count'))

    objects = LoginAttemptManager()

    class Meta:
        verbose_name = _('login attempt')
        verbose_name_plural = _('login attempts')
        ordering = ('-id',)
        permissions = (
            ('unlock', _('Unlock by username or IP address')),
        )

    def save(self, *args, **kwargs):
        if self.user_id is not None and not self.user_repr:
            self.user_repr = self.user.get_username()[:200] or 'NO USERNAME'
            if kwargs.get('update_fields'):
                kwargs['update_fields'].append('user_repr')
        super(LoginAttempt, self).save(*args, **kwargs)

    def __unicode__(self):
        return u'{0} at {1} from {2}'.format(self.username,
                                             self.timestamp,
                                             self.source_address)

class LockoutTracker(models.Model):
  loginAttempt = models.ForeignKey(LoginAttempt) 
    
  class Meta:
    verbose_name = _('LockoutTracker')
    verbose_name_plural = _('LockoutTrackers')



class PasswordChangeAdmin(models.Manager):
    def set_temporary_password(self, user):
        """Returns a random password and sets this as temporary password for
        provided user."""
        password = get_random_string(TEMP_PASSWORD_LENGTH, TEMP_PASSWORD_CHARS)

        pw_change = PasswordChange(user=user, is_temporary=True,
                                   successful=True)
        pw_change.set_password(password)
        pw_change.save()

        user.set_password(password)
        user.save()

        return password


class PasswordChange(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, verbose_name=_('user'),
                             blank=True, null=True, on_delete=models.SET_NULL)
    user_repr = models.CharField(_('user'), max_length=200)
    timestamp = models.DateTimeField(_('timestamp'), auto_now_add=True)
    successful = models.BooleanField(_('successful'), default=False)
    # 'is_temporary is used by 'user managers' to set a temporary password
    # for a user, this password must be changed at first login
    is_temporary = models.BooleanField(_('is temporary'), default=False)
    # Optionally keep password a history of hashes to prevent users from
    # reusing old passwords.
    password = models.CharField(_('password'), max_length=128, default='',
                                editable=False)

    objects = PasswordChangeAdmin()

    class Meta:
        verbose_name = _('password change')
        verbose_name_plural = _('password changes')
        ordering = ('-id',)

    def set_password(self, raw_password):
        self.password = make_password(raw_password)

    def save(self, *args, **kwargs):
        if self.user_id is not None and not self.user_repr:
            self.user_repr = self.user.get_username()[:200] or 'NO USERNAME'
            if kwargs.get('update_fields'):
                kwargs['update_fields'].append('user_repr')
        super(PasswordChange, self).save(*args, **kwargs)

    def __unicode__(self):
        return u'{0} at {1}'.format(self.user, self.timestamp)


class UserChange(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, verbose_name=_('user'),
                             blank=True, null=True, on_delete=models.SET_NULL)
    user_repr = models.CharField(_('user'), max_length=200)
    timestamp = models.DateTimeField(_('timestamp'), auto_now_add=True)
    by_user = models.ForeignKey(settings.AUTH_USER_MODEL,
                                verbose_name=_('by user'),
                                related_name='changed_users',
                                blank=True, null=True,
                                on_delete=models.SET_NULL)
    by_user_repr = models.CharField(_('by user'), max_length=200)

    class Meta:
        verbose_name = _('user change')
        verbose_name_plural = _('user changes')
        ordering = ('-id',)

    def save(self, *args, **kwargs):
        if self.user_id is not None and not self.user_repr:
            self.user_repr = self.user.get_username()[:200] or 'NO USERNAME'
            if kwargs.get('update_fields'):
                kwargs['update_fields'].append('user_repr')

        if self.by_user_id is not None and not self.by_user_repr:
            self.by_user_repr = (self.by_user.get_username()[:200] or
                                 'NO USERNAME')
            if kwargs.get('update_fields'):
                kwargs['update_fields'].append('by_user_repr')

        super(UserChange, self).save(*args, **kwargs)

    def __unicode__(self):
        return u'{0} at {1} by {1}'.format(self.user, self.timestamp,
                                           self.by_user)
