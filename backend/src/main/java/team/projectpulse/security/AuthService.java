package team.projectpulse.security;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import team.projectpulse.instructor.Instructor;
import team.projectpulse.instructor.converter.InstructorToInstructorDtoConverter;
import team.projectpulse.instructor.dto.InstructorDto;
import team.projectpulse.student.Student;
import team.projectpulse.student.converter.StudentToStudentDtoConverter;
import team.projectpulse.student.dto.StudentDto;
import team.projectpulse.user.MyUserPrincipal;
import team.projectpulse.user.PeerEvaluationUser;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
public class AuthService {

    private final JwtProvider jwtProvider;

    private final StudentToStudentDtoConverter studentToStudentDtoConverter;
    private final InstructorToInstructorDtoConverter instructorToInstructorDtoConverter;


    public AuthService(JwtProvider jwtProvider, StudentToStudentDtoConverter studentToStudentDtoConverter, InstructorToInstructorDtoConverter instructorToInstructorDtoConverter) {
        this.jwtProvider = jwtProvider;
        this.studentToStudentDtoConverter = studentToStudentDtoConverter;
        this.instructorToInstructorDtoConverter = instructorToInstructorDtoConverter;
    }

    // SpotBugs flags the principal cast below: Spring Security 7 declares
    // Authentication.getPrincipal() @org.jspecify.annotations.Nullable, so the principal
    // dereferenced on the next line is nullable to the analyzer. It cannot be null here:
    // createLoginInfo is reached only from AuthController.getLoginInfo, which serves
    // POST /users/login, and SecurityConfiguration marks that route .authenticated() -
    // BasicAuthenticationFilter has already produced an Authentication carrying the
    // MyUserPrincipal that UserService (this app's UserDetailsService) built. An Authentication
    // with a null principal is by definition unauthenticated and is refused before the
    // controller runs.
    // Checkable: "grep -rn createLoginInfo src/" names AuthController.getLoginInfo and nothing else,
    // and SecurityConfiguration has ".requestMatchers(HttpMethod.POST, baseUrl + \"/users/login\")
    // .authenticated()". If a second caller appears, or that route becomes permitAll, this
    // suppression is wrong and must come off.
    @SuppressFBWarnings(
            value = "NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE",
            justification = "Authenticated path only: POST /users/login is .authenticated(), so the principal is set.")
    public Map<String, Object> createLoginInfo(Authentication authentication) {
        // Create user info.
        MyUserPrincipal principal = (MyUserPrincipal) authentication.getPrincipal();
        PeerEvaluationUser peerEvaluationUser = principal.getPeerEvaluationUser();

        Map<String, Object> loginResultMap = new HashMap<>();

        if ("student".equals(peerEvaluationUser.getRoles())) {
            StudentDto studentDto = this.studentToStudentDtoConverter.convert((Student) peerEvaluationUser);
            // Create a JWT.
            String token = this.jwtProvider.createToken(authentication);
            loginResultMap.put("userInfo", studentDto);
            loginResultMap.put("token", token);
        } else if (peerEvaluationUser.getRoles().contains("instructor")) {
            InstructorDto instructorDto = this.instructorToInstructorDtoConverter.convert((Instructor) peerEvaluationUser);
            // Create a JWT.
            String token = this.jwtProvider.createToken(authentication);
            loginResultMap.put("userInfo", instructorDto);
            loginResultMap.put("token", token);
        }
        return loginResultMap;
    }

}
