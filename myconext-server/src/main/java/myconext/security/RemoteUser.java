package myconext.security;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class RemoteUser implements UserDetails, CredentialsContainer {

    private String username;
    private String password;
    private String institutionGUID;
    private String schacHome;
    private List<String> scopes;

    public RemoteUser(RemoteUser remoteUser) {
        this.username = remoteUser.username;
        this.password = remoteUser.password;
        this.institutionGUID = remoteUser.institutionGUID;
        this.schacHome = remoteUser.schacHome;
        this.scopes = remoteUser.scopes;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return scopes.stream()
                .map(scope -> new SimpleGrantedAuthority("ROLE_" + scope))
                .collect(Collectors.toList());
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public void eraseCredentials() {
        this.password = null;
    }

}
