package myconext.model;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.util.StringUtils;

import java.io.Serializable;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

@NoArgsConstructor
@AllArgsConstructor
@Getter
public class ExternalLinkedAccount implements Serializable {

    private String subjectId;
    private IdpScoping idpScoping;
    private VerifyIssuer issuer;
    @Setter
    private Verification verification;
    private String serviceUUID;
    private String serviceID;
    private String subjectIssuer;
    @Setter
    private String brinCode;

    private String initials;
    private String chosenName;
    private String firstName;
    private String preferredLastName;
    private String legalLastName;
    private String partnerLastNamePrefix;
    private String legalLastNamePrefix;
    private String preferredLastNamePrefix;
    private String partnerLastName;
    @Setter
    @Schema(type = "integer", format = "int64", example = "1634813554997")
    private Date dateOfBirth;
    @Schema(type = "integer", format = "int64", example = "1634813554997")
    private Date createdAt;
    @Schema(type = "integer", format = "int64", example = "1634813554997")
    private Date expiresAt;
    private boolean external = true;

    public ExternalLinkedAccount(String subjectId, IdpScoping idpScoping, boolean external) {
        this.subjectId = subjectId;
        this.idpScoping = idpScoping;
        this.external = external;
        this.expiresAt = Date.from(Instant.now().plus(5 * 365, ChronoUnit.DAYS));
    }

    public boolean areNamesValidated() {
        switch (this.idpScoping) {
            case idin:
                return StringUtils.hasText(initials) && StringUtils.hasText(legalLastName);
            case eherkenning:
                return StringUtils.hasText(firstName) && StringUtils.hasText(preferredLastName);
            case studielink:
                return StringUtils.hasText(firstName) && StringUtils.hasText(legalLastName) && !Verification.Ongeverifieerd.equals(verification);
            default:
                throw new IllegalArgumentException("Won't happen");
        }
    }

}
