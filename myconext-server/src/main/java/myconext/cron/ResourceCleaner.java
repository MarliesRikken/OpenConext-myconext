package myconext.cron;


import myconext.model.LinkedAccount;
import myconext.model.SamlAuthenticationRequest;
import myconext.model.User;
import myconext.repository.AuthenticationRequestRepository;
import myconext.repository.UserRepository;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;

import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import static myconext.security.GuestIdpAuthenticationRequestFilter.EDUPERSON_SCOPED_AFFILIATION_SAML;

@Component
public class ResourceCleaner {

    private static final Log LOG = LogFactory.getLog(ResourceCleaner.class);

    private final AuthenticationRequestRepository authenticationRequestRepository;
    private final UserRepository userRepository;
    private final boolean cronJobResponsible;

    @Autowired
    public ResourceCleaner(AuthenticationRequestRepository authenticationRequestRepository,
                           UserRepository userRepository,
                           @Value("${cron.node-cron-job-responsible}") boolean cronJobResponsible) {
        this.authenticationRequestRepository = authenticationRequestRepository;
        this.userRepository = userRepository;
        this.cronJobResponsible = cronJobResponsible;
    }

    @Scheduled(cron = "${cron.token-cleaner-expression}")
    public void clean() {
        if (!cronJobResponsible) {
            return;
        }
        Date now = new Date();
        info(SamlAuthenticationRequest.class, authenticationRequestRepository.deleteByExpiresInBeforeAndRememberMe(now, false));

        List<User> users = userRepository.findByLinkedAccounts_ExpiresAtBefore(now);
        users.forEach(user -> {
            List<LinkedAccount> linkedAccounts = user.getLinkedAccounts().stream()
                    .filter(linkedAccount -> linkedAccount.getExpiresAt().toInstant().isAfter(now.toInstant()))
                    .collect(Collectors.toList());
            user.setLinkedAccounts(linkedAccounts);
            LOG.info(String.format("Removed expired linked account for user %s", user.getEmail()));
            if (CollectionUtils.isEmpty(linkedAccounts)) {
                user.getAttributes().remove(EDUPERSON_SCOPED_AFFILIATION_SAML);
                LOG.info(String.format("Removed %s for user %s as there are no linked accounts anymore",
                        EDUPERSON_SCOPED_AFFILIATION_SAML, user.getEmail()));
            }
            userRepository.save(user);

        });
    }

    private void info(Class clazz, long count) {
        LOG.info(String.format("Deleted %s instances of %s in cleanup", count, clazz));
    }
}
