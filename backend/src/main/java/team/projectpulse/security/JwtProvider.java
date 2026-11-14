package team.projectpulse.security;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import team.projectpulse.user.MyUserPrincipal;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.stream.Collectors;

@Component
public class JwtProvider {

    private final JwtEncoder jwtEncoder;


    public JwtProvider(JwtEncoder jwtEncoder) {
        this.jwtEncoder = jwtEncoder;
    }

    // SpotBugs flags the cast of Authentication.getPrincipal(), which Spring Security declares
    // @Nullable, as a possible null dereference. It cannot be null here: createToken is called only
    // from AuthService.createLoginInfo (the only caller in src/), which runs only for
    // POST /users/login after BasicAuthenticationFilter has authenticated the request, and which
    // casts and dereferences the very same principal two statements earlier. An unauthenticated
    // Authentication never reaches a token mint.
    // Checkable: "grep -rn createToken src/" names AuthService.createLoginInfo and nothing else, and
    // SecurityConfiguration marks POST /users/login .authenticated(). If a second caller appears,
    // or one that is reachable unauthenticated, this suppression is wrong and must come off.
    @SuppressFBWarnings(
            value = "NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE",
            justification = "Authenticated path only: the sole caller already dereferenced this principal.")
    public String createToken(Authentication authentication) {
        Instant now = Instant.now();
        long expiresIn = 2; // 2 hours

        // Prepare a claim called authorities.
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(" "));// MUST BE space-delimited.

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("self")
                .issuedAt(now)
                .expiresAt(now.plus(expiresIn, ChronoUnit.HOURS))
                .subject(authentication.getName())
                .claim("userId", ((MyUserPrincipal) authentication.getPrincipal()).getPeerEvaluationUser().getId())
                .claim("authorities", authorities)
                .build();

        return this.jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

}
