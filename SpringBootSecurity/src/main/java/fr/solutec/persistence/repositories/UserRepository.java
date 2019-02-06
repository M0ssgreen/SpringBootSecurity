package fr.solutec.persistence.repositories;

import org.springframework.data.jpa.repository.JpaRepository;

import fr.solutec.persistence.entities.User;

public interface UserRepository extends JpaRepository<User, Long> {
    User findByUsername(String username);
}
