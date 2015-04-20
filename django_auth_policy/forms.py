import logging
from collections import OrderedDict

from django import forms
from django.utils.translation import ugettext_lazy as _
from django.utils.text import capfirst
from django.contrib.auth import authenticate, get_user_model

from django_auth_policy.models import PasswordChange
from django_auth_policy.handlers import (PasswordStrengthPolicyHandler,
                                         AuthenticationPolicyHandler,
                                         PasswordChangePolicyHandler)


logger = logging.getLogger(__name__)


class StrictAuthenticationForm(forms.Form):
    auth_policy = AuthenticationPolicyHandler()
    password_change_policy = PasswordChangePolicyHandler()

    username = forms.CharField(max_length=254)
    password = forms.CharField(label=_("Password"), widget=forms.PasswordInput)

    error_messages = {
        'invalid_login': _("Please enter a correct %(username)s and password. "
                           "Note that both fields may be case-sensitive."),
        'inactive': _("This account is inactive."),
    }


    def __init__(self, request, *args, **kwargs):
        """ Make request argument required
        """
        self.user_cache = None
        self.request = request
        super(StrictAuthenticationForm, self).__init__(*args, **kwargs)

        UserModel = get_user_model()
        self.username_field = UserModel._meta.get_field(UserModel.USERNAME_FIELD)
        if self.fields['username'].label is None:
            self.fields['username'].label = capfirst(self.username_field.verbose_name)

    def clean(self):
        remote_addr = (self.request.META.get('HTTP_X_REAL_IP') or
                self.request.META.get('REMOTE_ADDR'))
        if not remote_addr:
            logger.warning('Could not reliably determine source address',
                    extra={'path': self.request.get_full_path()})
            remote_addr = '127.0.0.1'

        host = self.request.get_host()
        username = self.cleaned_data.get('username')
        password = self.cleaned_data.get('password')

        attempt = self.auth_policy.pre_auth_checks(username, password,
                                                   remote_addr, host)

        if username and password:
            self.user_cache = authenticate(username=username, password=password)
            if self.user_cache is None:
                logger.info(u'Authentication failure, username=%s, '
                            'address=%s, invalid authentication.',
                            attempt.username, attempt.source_address)
                raise forms.ValidationError(
                        self.error_messages['invalid_login'],
                        code='invalid_login',
                        params={'username': self.username_field.verbose_name},
                        )
            else:
                attempt.user = self.user_cache
                attempt.save(update_fields=['user'])

                attempt = self.auth_policy.post_auth_checks(attempt)
                attempt = self.auth_policy.auth_success(attempt)

                self.password_change_policy.update_session(self.request,
                        self.user_cache)

        return self.cleaned_data

    def get_user_id(self):
        if self.user_cache:
            return self.user_cache.id
        return None

    def get_user(self):
        return self.user_cache



class StrictSetPasswordForm(forms.Form):
    password_strength_policy = PasswordStrengthPolicyHandler()
    error_messages = {
        'password_mismatch': _("The two password fields didn't match."),
        }
    new_password1 = forms.CharField(label=_("New password"),
                                    widget=forms.PasswordInput)
    new_password2 = forms.CharField(label=_("New password confirmation"),
                                    widget=forms.PasswordInput)

    def __init__(self, user, *args, **kwargs):
        self.user = user
        super(StrictSetPasswordForm, self).__init__(*args, **kwargs)

    def clean_new_password1(self):
        pw = self.cleaned_data.get('new_password1')
        self.password_strength_policy.validate(pw, self.user)
        return pw

    def clean_new_password2(self):
        password1 = self.cleaned_data.get('new_password1')
        password2 = self.cleaned_data.get('new_password2')
        if password1 and password2:
            if password1 != password2:
                raise forms.ValidationError(
                    self.error_messages['password_mismatch'],
                    code='password_mismatch',
                )
        return password2

    def is_valid(self):
        valid = super(StrictSetPasswordForm, self).is_valid()
        if self.is_bound:
            PasswordChange.objects.create(user=self.user, successful=valid,
                                          is_temporary=False)
            if valid:
                logger.info('Password change successful for user %s',
                            self.user)
            else:
                logger.info('Password change failed for user %s',
                            self.user)
        return valid

    def save(self, commit=True):
        self.user.set_password(self.cleaned_data['new_password1'])
        if commit:
            self.user.save()
        return self.user


class StrictPasswordChangeForm(StrictSetPasswordForm):
    error_messages = {
        'password_mismatch': _("The two password fields didn't match."),
        'password_incorrect': _("Your old password was entered incorrectly. "
                                "Please enter it again."),
        'password_unchanged': _("The new password must not be the same as "
                                "the old password"),
        }
    old_password = forms.CharField(label=_("Old password"),
                                   widget=forms.PasswordInput)

    def clean_old_password(self):
        """
        Validates that the old_password field is correct.
        """
        old_password = self.cleaned_data["old_password"]
        if not self.user.check_password(old_password):
            raise forms.ValidationError(
                self.error_messages['password_incorrect'],
                code='password_incorrect',
            )
        return old_password

    def clean_new_password1(self):
        pw = super(StrictPasswordChangeForm, self).clean_new_password1()

        # Check that old and new password differ
        if (self.cleaned_data.get('old_password') and
                self.cleaned_data['old_password'] == pw):

            raise forms.ValidationError(
                self.error_messages['password_unchanged'],
                'password_unchanged')

        return pw


StrictPasswordChangeForm.base_fields = OrderedDict(
    (k, StrictPasswordChangeForm.base_fields[k])
    for k in ['old_password', 'new_password1', 'new_password2']
)
