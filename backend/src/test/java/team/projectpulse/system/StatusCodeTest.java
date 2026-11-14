package team.projectpulse.system;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Constructor;
import java.lang.reflect.Modifier;

import static org.assertj.core.api.Assertions.assertThat;

class StatusCodeTest {

    @Test
    void utilityClassConstructorShouldBePrivate() {
        Constructor<?>[] constructors = StatusCode.class.getDeclaredConstructors();

        assertThat(constructors).hasSize(1);
        assertThat(Modifier.isPrivate(constructors[0].getModifiers())).isTrue();
    }
}
