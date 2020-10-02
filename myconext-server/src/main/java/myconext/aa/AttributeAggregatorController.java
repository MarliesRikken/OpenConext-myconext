package myconext.aa;

import myconext.exceptions.UserNotFoundException;
import myconext.manage.ServiceNameResolver;
import myconext.model.User;
import myconext.repository.UserRepository;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;


@RestController
@RequestMapping("/myconext/api")
public class AttributeAggregatorController {

    private static final Log LOG = LogFactory.getLog(AttributeAggregatorController.class);

    private final UserRepository userRepository;
    private final ServiceNameResolver serviceNameResolver;

    public AttributeAggregatorController(UserRepository userRepository,
                                         ServiceNameResolver serviceNameResolver) {
        this.userRepository = userRepository;
        this.serviceNameResolver = serviceNameResolver;
    }

    @GetMapping(value = {"attribute-aggregation"})
    @PreAuthorize("hasRole('ROLE_attribute-aggregation')")
    public ResponseEntity<List<UserAttribute>> aggregate(@RequestParam("sp_entity_id") String spEntityId,
                                                         @RequestParam("eduperson_principal_name") String eduPersonPrincipalName) {
        Optional<User> userOptional = userRepository
                .findUserByLinkedAccounts_eduPersonPrincipalName(eduPersonPrincipalName);
        List<UserAttribute> userAttributes = new ArrayList<>();
        userOptional.ifPresent(user -> {
            Optional<String> optionalEduID = user.computeEduIdForServiceProviderIfAbsent(spEntityId,
                    serviceNameResolver.resolve(spEntityId, "en"),
                    serviceNameResolver.resolve(spEntityId, "nl"));
            optionalEduID.ifPresent(eduID -> userAttributes.add(
                    new UserAttribute("urn:mace:eduid.nl:1.1", eduID)));
        });

        LOG.debug(String.format("Attribute aggregation response %s", userAttributes));

        return ResponseEntity.ok(userAttributes);
    }

    //Note that the spEntityId is the same as the  OIDC client ID
    @GetMapping(value = "attribute-manipulation")
    @PreAuthorize("hasRole('ROLE_attribute-manipulation')")
    public ResponseEntity<Map> manipulate(@RequestParam("sp_entity_id") String spEntityId,
                                          @RequestParam("uid") String uid,
                                          @RequestParam(value = "sp_institution_guid", required = false) String spInstitutionGuid) {
        User user = userRepository.findUserByUid(uid).orElseThrow(UserNotFoundException::new);
        String serviceProviderName = serviceNameResolver.resolve(spEntityId, "en");
        String serviceProviderNameNl = serviceNameResolver.resolve(spEntityId, "nl");

        boolean needToSave = user.eduIdForServiceProviderNeedsUpdate(spEntityId, serviceProviderName, serviceProviderNameNl);
        String eduId = user.computeEduIdForServiceProviderIfAbsent(spEntityId, serviceProviderName, serviceProviderNameNl).get();
        if (needToSave) {
            userRepository.save(user);
        }
        Map<String, String> result = new HashMap<>();
        result.put("eduid", eduId);
        if (StringUtils.hasText(spInstitutionGuid)) {
            user.getLinkedAccounts().stream()
                    .filter(linkedAccount -> linkedAccount.getInstitutionIdentifier().equals(spInstitutionGuid))
                    .findFirst()
                    .ifPresent(linkedAccount -> result.put("eduperson_principal_name", linkedAccount.getEduPersonPrincipalName()));
        }

        LOG.debug(String.format("Attribute manipulation response %s", result));

        return ResponseEntity.ok(result);
    }


}
